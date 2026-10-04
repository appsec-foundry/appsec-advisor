# On-demand threat analysis

Status: the operator approved the wording below on 2026-10-04. The `REQ-FLW-002` and `P-1` changes are applied; the `REQ-ANA` requirements land as described under [Landing order](#landing-order).

## Problem

The [implementation plan](../../../docs/proposals/security-advisor-threat-analyst-implementation-plan.md) adds a voluntary threat analysis for design questions and bounded change reviews, with a manual skill and an advisory CI entry point. The product promises it makes have no requirement, and two existing rules would block or contradict it as written. The [work package 1 results](../../../docs/proposals/security-advisor-threat-analyst-wp1-results.md) record the mapping.

`REQ-FLW-002` requires complete STRIDE coverage for every analyzed component in every depth mode. A bounded change review analyzes components without full STRIDE coverage, so it would violate the requirement.

Principle `P-1` states that there is no second orchestrator. The analysis needs its own controller because the assessment controller is protected from analyst changes. Its rationale concerns the assessment: a second scheduler would split where turn and context admission are decided.

## Goal

The catalog states what a developer can rely on from an on-demand analysis: it runs only when asked, it does not hide failure, it leaves the threat model and assessments alone, organization-required inputs hold, optional question packages and the Manifesto profile guide without deciding, and saved answers persist only on request. `REQ-FLW-002` and `P-1` keep their meaning for the assessment and no longer contradict a separate workflow.

## Non-goals

- Changing any assessment behavior, coverage, or depth mode.
- Automatic activation, hooks, blocking gates, or updates to the canonical threat model. These need separate proposals.
- Requirement grading by the analysis. The existing reviewer keeps that role.

## Approach

### Requirement changes

`REQ-FLW-002` keeps its ID and title. Its text becomes:

> Every component a threat-model assessment analyzes is checked against all six STRIDE categories in every depth mode. Cost and pacing choices may not silently reduce that coverage.

A new section `## On-demand threat analysis` follows `## After the run`:

> ### REQ-ANA-001 — Threat analysis runs only when someone asks for it
>
> Installing the plugin, configuring an organization profile, or selecting question packages or a methodology profile never starts a threat analysis. It runs when a developer invokes it or a team configures it in its own CI.
>
> ### REQ-ANA-002 — An advisory analysis never reports a failure as success
>
> A complete analysis succeeds regardless of its findings and grants no security approval. Invalid input, missing required context or answers, and incomplete required work end without success.
>
> ### REQ-ANA-003 — Threat analysis leaves the threat model and assessments untouched
>
> An analysis never changes the threat model or its finding identities. Its completion, failure, or cancellation leaves any assessment intact, including one running at the same time.
>
> ### REQ-ANA-004 — Required analysis inputs cannot be weakened
>
> A developer can add question packages and methodology profiles to an analysis but cannot remove inputs the organization requires. A change under review cannot choose the inputs that assess it.
>
> ### REQ-ANA-005 — Questions and methodology guide the analysis without deciding it
>
> Question packages and methodology profiles direct what the analysis investigates. They cannot establish a vulnerability or requirement violation on their own or grant the analysis additional permissions.
>
> ### REQ-ANA-006 — The Threat Modeling Manifesto profile is optional
>
> The plugin provides a methodology profile based on the Threat Modeling Manifesto. It applies only when selected, names its source, and does not certify compliance.
>
> ### REQ-ANA-007 — Answers are saved only on request
>
> Answers to analysis questions last for the session unless the developer saves them to a feature file of their choice. Saving never commits and never changes business context or the threat model, and a saved answer is rechecked before reuse.
>
> ### REQ-ANA-008 — A change review states how each finding relates to the change
>
> Each finding of a change review states whether the change introduced, worsened, or mitigated it, whether it existed before, or that the relationship is unknown.

### Decision register change

`P-1` becomes:

> **P-1 One control plane per workflow.** The threat-model assessment has one orchestrator, and compaction is not the primary optimization. A second scheduler inside the assessment would split the place where turn and context admission are decided. A separate workflow may own its controller only if it dispatches no assessment roles and shares no assessment state.

### Landing order

`check_specs.py` requires a binding for every active requirement, and a binding must match existing files and name existing tests. The `REQ-FLW-002` and `P-1` wording can land as soon as it is approved, because their bindings and guards do not change. Each `REQ-ANA` requirement enters the catalog in the work package that creates its first bound file and guard test, together with its binding. An approved requirement that has not landed yet stays listed in `tasks.md`.

Landed so far: `REQ-FLW-002`, `P-1`, `REQ-ANA-003` (work package 2), and `REQ-ANA-001`, `REQ-ANA-002`, and `REQ-ANA-004` through `REQ-ANA-008` (work packages 3 to 5).

## Open review points

- Decision `P-7` asks for one vocabulary per concept. The analysis returns exit code 2 for rejected input, while the assessment uses its own reject code under `OR-14`. Review in work package 2 whether the analysis adopts the assessment's codes or documents a separate contract.
- `REQ-ANA-004` assumes the organization-profile extension described in the work package 1 results. If that extension is deferred, the requirement lands with the extension rather than earlier.
