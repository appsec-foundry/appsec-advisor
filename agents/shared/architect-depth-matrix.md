# Architect-reviewer depth-dependent behavior

Used by `appsec-architect-reviewer`. Controls which of the 13 checks run at each `ASSESSMENT_DEPTH`. When a check is skipped, the agent still emits the `STEP_START` and `STEP_END` log entries with message `Skipped (<depth> depth)` so the log is uniform. When a check is `subsumed` by another, emit a `STEP_START` / `STEP_END` pair with message `Subsumed by Check N` and produce no findings.

| Check | `quick` | `standard` | `thorough` |
|-------|---------|-----------|------------|
| 1 — Architecture ↔ Recon | skip | run | run |
| 2 — Trust Boundary Completeness | run | run | run |
| 3 — Summary Verdict Plausibility | run | run | run |
| 4 — Threat Coverage Gaps | skip | run (core heuristics only) | run (all heuristics) |
| 5 — Mitigation Realism | run (top-3 Critical/High only) | run | run |
| 6 — CVSS ↔ L×I Alignment | run | subsumed by Check 10 D4 | subsumed by Check 10 D4 |
| 7 — Finding Correlation Clusters | skip | run | run |
| 8 — Attack Path Narrative | skip | run (top 2 paths) | run (top 3 paths) |
| 9 — Architectural-Finding Adequacy | skip | run | run |
| 10 — Rating Coherence (D1–D4) | skip | run (D1, D4 only) | run (D1–D4) |
| 11 — Design Decision Impact | skip | run | run |
| 12 — Remediation Synergy / ROI | skip | run | run |
| 13 — Config/IaC Review | skip | run (if artefact exists) | run (if artefact exists) |
