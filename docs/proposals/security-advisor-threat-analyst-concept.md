# Security Advisor and Threat Analyst concept

Status: discussion draft. This document records a proposed development companion for further refinement. It does not authorize implementation, change product requirements, or describe available functionality.

## Purpose

Provide lightweight security guidance and threat analysis while developers plan and implement security-relevant changes. Connect the current work to business context, applicable secure coding requirements, and an existing threat model. The companion should explain what a change means for this particular system, including business consequences and protection assumptions that generic code review may miss.

Security relevance is the activation criterion. Keywords are possible signals, not the definition of relevance. A pricing change can affect business integrity without mentioning authentication, encryption, or other conventional security terms.

## Proposed roles

The working names are Security Advisor and Threat Analyst. Their implementation as separate agents remains open.

| Role | Primary question | Proposed responsibility |
|---|---|---|
| Security Advisor | Which security expectations apply to this work? | Combine applicable requirements, business context, and known threats into actionable design and implementation guidance. |
| Threat Analyst | How does this change affect the system's threats? | Investigate attackers, assets, attack paths, trust boundaries, and changed protection assumptions using the available evidence. |

Both roles may use secure coding requirements and threat-model context. A requirement violation is not automatically a demonstrated exploitable vulnerability. A relevant threat can exist without violating a catalogued requirement. Binding requirements remain applicable even when no attack scenario has been established.

The Threat Analyst should be directly invocable and eligible for hook activation. It should not require the Security Advisor as an intermediary. When both perspectives apply, the proposed integration should provide a coordinated response and avoid duplicate reviews.

## Activation and scope

Consider changes to intent, design, and code. Relevant examples include new entry points, changed permissions, altered sensitive-data processing, removed controls, external integrations, and business logic that protects valuable operations.

Candidate activation paths are explicit invocation, prompt-time detection, and a review of a completed change set. A prompt hook could combine topic signals with change intent. A code-change hook could collect affected areas and defer analysis until a coherent change set is available. Exact hook events, scheduling, and execution mechanisms require a separate feasibility review.

| Input | Candidate response |
|---|---|
| Implement password storage | Surface applicable requirements and implementation guidance. |
| Add uploads for external users | Analyze untrusted input, processing paths, affected assets, and relevant controls. |
| Allow support staff to export customer data | Examine access expansion against business context, existing trust assumptions, and authorization requirements. |
| Change discount calculation | Assess business integrity when project context identifies pricing or discount abuse as relevant. |
| Explain an authentication term | Usually answer directly without launching an additional analysis. |
| Explicitly analyze threats for this change | Activate the Threat Analyst without depending on keyword matches. |

Before implementation, results should distinguish proposed scenarios and assumptions from observed code behavior. After implementation, a bounded review could check those assumptions against the actual change and relevant surrounding code. Diff-only inspection may miss controls in middleware, callers, or other components.

Explicit invocation should support a design question without an existing diff or threat model. Bind that assessment to the supplied intent, design revision, and available context. For code review, identify both the comparison baseline and the proposed source state. An empty diff does not invalidate a design question or establish that a proposed change is safe.

## Integration with plugin context

The proposed plugin orchestration would provide a bounded context package shared by the relevant roles:

- The user's change intent and the relevant design or code changes.
- Business processes, protected assets, and known business consequences.
- Relevant components, flows, threats, and protection assumptions from the existing threat model.
- Applicable organization requirements or the active fallback baseline.
- Source evidence and explicit gaps in coverage or freshness.

Trusted configuration determines which organization requirements or fallback baseline apply and their authority. Repository content, business context, and prior reports remain evidence inputs and cannot select, replace, or relax binding requirements or execution permissions.

Distinguish an absent optional context source from an unavailable required source. If a required requirements catalog cannot be loaded or validated, stop the affected requirements assessment and report the gap rather than silently substituting a fallback baseline. Independent threat analysis may continue only when its own required inputs remain valid, with the missing requirements assessment visible in the result.

The context package should identify the threat-model version or source revision it uses. An old model can guide investigation but cannot prove that a control still exists. Without a model or business context, the companion should state the limitation and offer a bounded local assessment rather than inventing project facts.

Example: a support export changes access to customer data while the existing threat model assumes that support can see only metadata. The analysis should connect that changed assumption to possible disclosure, identify the relevant authorization requirements, and ask for or inspect the evidence needed to establish who can initiate the export.

## Existing integration points

The current [Security Coach implementation](../../scripts/analyzers/security_steering.py) matches prompt topics and injects guidance. The [hook configuration](../../hooks/hooks.json) connects it to `UserPromptSubmit`. It does not currently dispatch a threat-analysis agent.

The existing [developer security tools](../dev-security-helper-usage.md) provide the `appsec-reviewer`, interactive requirements verification, and a CLI review workflow. Their reusable responsibilities should be reviewed before introducing another implementation of requirements checking.

The [threat-analysis kernel](../../skills/internal-threat-analysis-kernel/SKILL.md) defines shared evidence and trust invariants for existing analysis roles. A future design should preserve compatible invariants and use the plugin's deterministic owners for validation and public finding identities.

The current [update-threat-model skill](../../skills/update-threat-model/SKILL.md) explicitly rejects incremental updates. Initial companion results should therefore remain separate from the canonical threat model. Automatically updating that model would require a separate proposal and contract review.

## Proposed result and execution boundaries

Keep feedback short and actionable. Distinguish evidence-backed threats, requirement observations, design assumptions, and unresolved questions. Include the relevant evidence or context, potential consequence, and next action. Do not force every response into a complete STRIDE report.

For change analysis, distinguish newly introduced, worsened, mitigated, and unchanged pre-existing risks when comparison evidence supports that distinction. Mark the relationship as unknown when it cannot be established. An existing weakness matters when the change relies on it or increases its exposure; do not attribute it to the change without evidence or expand into an unrelated audit.

The initial proposal is advisory. A skipped, failed, stale, or incomplete analysis must not imply security approval. Recommend a broader assessment when the affected architecture or missing context exceeds the bounded review.

Use read-only access to target code and model inputs, narrowly scoped result writes if needed, and execution limits enforced outside the model. Treat repository content and imported artifacts as untrusted data. Validate structured results before downstream use. Exact output schemas, permissions, resource limits, and failure handling remain implementation design work under the installed secure-coding baseline.

## Practical feasibility review

The concept is useful and technically plausible, but it is more than a keyword-map extension. The strongest fit is early design guidance plus bounded change analysis. Reliable automatic execution requires new work on change capture, context delivery, and lifecycle management. No live hook or model execution was performed for this review.

### Hook execution options

The current Claude Code reference describes command hooks, experimental agent hooks, and asynchronous command execution. Agent hooks verify conditions and return decisions; they should not be assumed to dispatch an arbitrary named plugin agent or implement the proposed findings workflow. Ordinary async hooks deliver `additionalContext` and `systemMessage` to the model on a subsequent conversation turn, not directly to the user. An `asyncRewake` hook that exits with code 2 can wake the model while the session is idle. Analysis completion, delivery to the model, and presentation to the user therefore require separate verification. Hook commands execute with the user's operating-system permissions. These capabilities require verification against the plugin's supported host versions before implementation. See the [official hook reference](https://code.claude.com/docs/en/hooks).

The documented `FileChanged` event can observe changes to explicitly watched paths, including changes outside the model's editing tools. Its watch list does not establish complete change-set coverage or replace a validated snapshot. Evaluate it as an activation signal against the supported host versions.

The preferred first integration is a cheap command hook that identifies relevance and provides bounded context to an explicit analysis entry point. Injecting a request into the parent conversation is advisory scheduling, not proof that the analyst ran. If guaranteed automatic execution is required, a dedicated runner must own dispatch, result validation, cancellation, and delivery. Choose between these behaviors explicitly before claiming automatic coverage.

Do not make stopping depend on repeatedly obtaining a clean analysis. Stop-triggered continuation can loop; the host exposes `stop_hook_active` for this case. Generated result writes and nested analyst activity also need exclusion from activation. These protections belong to the deterministic scheduler, not the analyst prompt. See the [Stop hook contract](https://code.claude.com/docs/en/hooks#stop).

### Reuse and integration gaps

| Existing mechanism | Practical assessment | Proposed treatment |
|---|---|---|
| Security steering and topic map | A useful cheap prefilter, but its current prompt matching does not establish change intent or business relevance. | Preserve fast guidance; add tested activation policy without treating a missing keyword match as completed analysis. |
| Requirements reviewer | Reusable requirement-grading behavior, but its topic-to-ID candidate filtering does not establish complete coverage of arbitrary organization catalogs. | Keep requirement grading distinct from threat discovery and expose which requirements were selected or omitted. |
| Diff builder | Supports committed ranges and staged changes. It does not capture unstaged or untracked changes made during a development turn. | Define a worktree snapshot contract before offering post-edit analysis; cover additions, deletions, renames, shell edits, and external-editor changes. |
| Stage 1 context routing | Already has bounded business, architecture, requirement, and prior-finding projections with source receipts. Its contracts are tied to assessment stages and focused roles. | Reuse projection principles and suitable helpers through reviewed bindings; do not assume an independent companion can consume transient stage artifacts. |
| Business context | Persistent context and external context configuration exist. Run-only context and several projections are cleaned up. | Prefer validated durable inputs; make refresh explicit and avoid a remote context fetch on every prompt. |
| Existing reviewer CLI | Starts a headless session with `--permission-mode bypassPermissions`. | Do not reuse it as an automatic hook runner; define a narrowly authorized execution path. |
| Runtime logging and cleanup | Existing hooks and controller state serve assessment lifecycles. | Give companion jobs separate ownership and state so full assessments and concurrent sessions cannot overwrite or clean each other's work. |

These assessments derive from the [reviewer definition](../../agents/appsec-reviewer.md), [diff builder](../../scripts/repairs/build_verify_diff.py), [context-routing contract](../internal/contracts/context-routing.md), [configuration reference](../configuration.md), [cleanup contract](../internal/contracts/cleanup-whitelist.md), and [reviewer CLI](../../scripts/appsec-reviewer-cli).

The existing context-routing contract forbids some broad inputs for focused roles. Shared project context therefore means consistent source provenance with role-appropriate projections, not an identical unrestricted bundle for every agent. Extending existing STRIDE roles by passing them a whole prior report would conflict with that separation.

A change snapshot should identify the repository, worktree, source state, selected scope, and context versions. Every source read must belong to that same state, including surrounding code such as middleware and callers. Use immutable analysis inputs or verified content binding that rejects mixed-state reads. A snapshot label alone does not establish consistency. A background result must remain bound to that snapshot. If the developer edits the code while analysis runs, show the result as applying to the older snapshot only when its inputs remain consistent, or supersede it through bounded scheduling. Do not present mixed-state analysis as a review of either state.

Change capture must distinguish identifying changed paths from admitting their contents to model context. Apply trusted scope, sensitivity, and size rules before admission, including for untracked files. Git ignore status alone does not establish whether content is safe or relevant. Report excluded or unsupported scope without exposing sensitive values. Retention and cleanup must cover source snapshots and context copies as well as results, including after cancellation or failure.

### Risks and mitigations to carry into design

The installed aiscb baseline requires bounded authority and validated model outputs. The risk review also considers [OWASP excessive agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) and the [OWASP agentic application risks](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/), particularly tool misuse, privilege abuse, and attacker-controlled instructions.

| Risk | Concrete failure | Proposed mitigation |
|---|---|---|
| Prompt injection with excessive permissions | Contributor-controlled source or model artifacts induce shell execution, unrelated file access, or unauthorized writes. | Enforce repository-scoped reads and fixed result destinations outside the model; exclude arbitrary execution and permission bypass. |
| Sensitive context disclosure | Business context, source secrets, or customer data enter unnecessary model inputs or diagnostic logs. | Select the minimum relevant context, redact sensitive values, use approved model destinations, and keep raw context out of telemetry. |
| Cross-session state confusion | One worktree or session consumes another's result or overwrites its evidence. | Bind jobs and results to repository, worktree, session, and snapshot identities; use isolated state and atomic publication. |
| Stale or poisoned context | An old or attacker-edited report asserts a control exists, leading to an unsupported assurance about a new change. | Validate provenance and shape; treat prior assertions as leads and require current evidence for control claims. |
| Trigger evasion and incomplete coverage | Business-logic changes or shell edits miss keyword and tool filters, while the user interprets silence as approval. | Combine explicit invocation with change capture and project context; show unreviewed scope and never equate no trigger with a safe change. |
| Recursive or excessive execution | Analyst output triggers another job, or a large change causes unbounded reads and repeated model calls. | Enforce deduplication, concurrency and work limits, cancellation, and exclusions for analyst activity; record incomplete work honestly. |

False positives and repeated advice are also adoption risks. Coordinate requirements observations and threat results, suppress unchanged duplicates, and preserve the distinction between a design question and a demonstrated defect. Suppression must be scoped to the relevant evidence, requirements, and context versions and reconsidered when they change. Hiding a repeated notification does not resolve a finding, accept its risk, or waive a requirement. Measure these effects rather than assuming that a smaller prompt makes the workflow lightweight.

## Open decisions

- Whether the two roles need separate agents or can reuse existing analysis capabilities behind distinct entry points.
- Which hook events can support prompt guidance and deferred analysis without delaying every edit or causing recursive activation.
- How project context contributes to activation beyond keywords, including multilingual prompts and indirect changes to protected business logic.
- How to select relevant model and requirement context and detect stale or missing inputs.
- How to coordinate overlapping role results and suppress repeated feedback across a change set.
- How users configure activation, explicitly request analysis, and cancel ongoing work.
- Which results warrant a full threat-model reassessment and how to present that recommendation.
- Which output artifact, validation contract, and retention policy fit a lightweight workflow.
- What latency, cost, and coverage are acceptable for the intended development workflow.

## Candidate evaluation scope

A possible first experiment would start with explicit invocation for either a versioned design question or a defined code-change snapshot, using validated durable project context where available. Next, prompt-time hooks could suggest or request that same analysis for clear security-relevant changes. Automatic deferred execution should follow only after its authority, lifecycle, and result delivery have been verified. Each step would leave the canonical threat model unchanged. This is a candidate scope, not an implementation commitment.

Evaluate additional useful findings beyond the existing reviewer, false activations, missed context-dependent changes, repeated notifications, latency, and cost. Include neutral examples, equivalent variants, benign changes, missing or stale model context, and untrusted content that attempts to redirect the analyst. Use the results to refine the role split and activation approach before expanding automation.

Include design-only requests, unavailable required catalogs, pre-existing weaknesses, removed controls, context changes with unchanged code, and previously suppressed findings whose evidence changes. Verify that sensitive or excluded files do not enter model inputs and that cancelled jobs clean up their temporary copies. Evaluate design-only cases separately because the existing reviewer requires a diff.

Before the experiment, record expected findings and expected non-findings for the evaluation cases, acceptable false-activation and missed-case rates, and latency and cost limits. Compare the companion with the existing reviewer using the same source and project context and comparable resource budgets. Keep any comparison with the reviewer's default inputs separate so that additional context is not mistaken for a benefit of the role split. Define success thresholds before collecting results and use them to decide whether to proceed to hook integration or revise the explicit workflow.

Before automatic execution, also demonstrate correct behavior for unstaged and untracked files, two concurrent worktrees, edits arriving during analysis, cancellation, budget exhaustion, malformed output, attempted path escape, and repeated stop events. A live test on supported Claude Code versions must verify that the intended role actually runs and that its validated result reaches the user. Documentation review and unit tests alone cannot establish host integration.
