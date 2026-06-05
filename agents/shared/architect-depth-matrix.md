# Architect-reviewer depth-dependent behavior

Used by `appsec-architect-reviewer`. Controls which of the 13 checks run at each `ASSESSMENT_DEPTH`. When a check is skipped, the agent still emits the `STEP_START` and `STEP_END` log entries with message `Skipped (<depth> depth)` so the log is uniform. When a check is `subsumed` by another, emit a `STEP_START` / `STEP_END` pair with message `Subsumed by Check N` and produce no findings.

**Detection vs. judgment (Sprint-3).** The `Det?` column marks checks whose **detection** is performed by `scripts/architect_structural_checks.py` (consumed from the mandatory pre-pass JSON). For those rows the LLM does **not** re-detect at any depth — it only handles the small judgment residue named in the agent's check body (e.g. Check 5 framework-bypass, Check 14 Unsafe-vs-Missing, Check 12 ROI-story synthesis). `det*` = detection deterministic, judgment residue remains; `det` = fully deterministic, no residue.

| Check | `Det?` | `quick` | `standard` | `thorough` |
|-------|--------|---------|-----------|------------|
| 1 — Architecture ↔ Recon | det* | skip | run | run |
| 2 — Trust Boundary Completeness | — | run | run | run |
| 3 — Summary Verdict Plausibility | det* | run | run | run |
| 4 — Threat Coverage Gaps | — | skip | run (core heuristics only) | run (all heuristics) |
| 5 — Mitigation Realism | det* | run (top-3 Critical/High only) | run | run |
| 6 — CVSS ↔ L×I Alignment | det | run | subsumed by Check 10 D4 | subsumed by Check 10 D4 |
| 7 — Finding Correlation Clusters | — | skip | run | run |
| 8 — Attack Path Narrative | — | skip | run (top 2 paths) | run (top 3 paths) |
| 9 — Architectural-Finding Adequacy | — | **deprecated (skip)** | **deprecated (skip)** | **deprecated (skip)** |
| 10 — Rating Coherence (D1–D4) | — | skip | run (D1, D4 only) | run (D1–D4) |
| 11 — Design Decision Impact | — | skip | run | run |
| 12 — Remediation Synergy / ROI | det* | skip | run | run |
| 13 — Config/IaC Review | det | skip | run (if artefact exists) | run (if artefact exists) |
| 14 — §7 Quality Bar | det* | skip | run (post-render) | run (post-render) |
| 15 — Actor Coverage | det* | skip | run (if actor layer) | run (if actor layer) |
