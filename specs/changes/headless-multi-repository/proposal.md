# Assess multiple repositories as one system

Status: Approved by the operator on 2026-10-07 through the implementation request following review and correction of the multi-repository plan.

Extend headless threat-model assessments to accept repeated `--repo` selections of local Git checkouts and an explicit output directory outside those checkouts. Every selected repository receives fresh discovery. One canonical model records repository-qualified components, sources, and evidenced connections. Figure 1 and exports retain that identity and distinguish unresolved connections from established topology.

The approved first delivery supports full assessments and resume with unchanged admitted input state. It preserves existing single-repository behavior. Incremental multi-repository assessment, remote cloning, interactive selection, nested overlapping checkouts, and separate per-repository reports are outside this delivery.

The target in REQ-PUR-001, REQ-PUR-003, REQ-MOD-001, REQ-MOD-005, and REQ-TRU-001 becomes the explicitly selected repository set. Required coverage and invalid-input behavior stay in REQ-FLW-002 and REQ-FLW-003. Existing report, evidence, trust-boundary, severity, export, and compatibility requirements continue to apply to the combined model. This approval does not permit weakening those controls.

The implementation follows [the reviewed plan](../../../docs/internal/analysis/implplan-headless-multi-repository-2026-10-07.md). Multi-repository admission remains unavailable to assessment runs until the host boundary, source identity, combined architecture, STRIDE coverage, report consistency, lifecycle, and publication gates work together. A parser-only change or several independent single-repository reports does not satisfy this proposal.

Acceptance requires neutral fresh-scan fixtures, a renamed variant, negative connections that remain disconnected, boundary abuse tests through the actual model host, deterministic replay, and a live full assessment with repository-qualified findings and readable figures. Tool-less host smoke tests and schema validation alone do not establish end-to-end completion.
