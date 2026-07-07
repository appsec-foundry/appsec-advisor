# Architect repair-plan classifier

Used by `appsec-architect-reviewer` after the 13 checks run. Classifies each warning into **content** (advisory) vs. **technical defect** (blocking). A technical defect is one that the fragment-driven renderer can fix in a repair round. The table below is the authoritative classifier — when any row classifies a finding as `yes`, the agent writes `$OUTPUT_DIR/.architect-repair-plan.json` with the corresponding `fragments_to_rewrite` and remediation guidance.

| Check finding | Technical defect? | Repair action (fragment) |
|---|---|---|
| Check 1 `invented component` / `missing service in model` | yes | rewrite `.fragments/architecture-diagrams.md` and/or `.fragments/system-overview.md` |
| Check 1 `label mismatch` | no — advisory | — |
| Check 2 `missing boundary` when §7.11 lacks it | yes | rewrite `.fragments/security-architecture.md` |
| Check 3 `summary verdict mismatch` | yes | rewrite `.fragments/ms-verdict.json` |
| Check 4 `threat coverage gap` | no — the threat-analyst should add the missing threat in the next full run | — |
| Check 5 `mitigation realism` | no — mitigation content is threat-analyst authoring | — |
| Check 7 `cluster missing` | no — narrative | — |
| Check 8 `no minimal cut P1` | no — narrative | — |
| Check 9 `af_cluster_missing` | no — orchestrator concern for the next full run | — |
| Check 10 `coherence_D1_*` cap violation | no — content drift | — |
| Check 11 `design decision uninvestigated` | no — narrative | — |
| Check 12 `high_roi_mitigation_not_prioritized` | no — narrative | — |
| §3 Attack Walkthroughs — missing `sequenceDiagram` for a Critical finding | yes | rewrite `.fragments/attack-walkthroughs.md` |
| §7 v2 Security Architecture — missing required H3, missing H4 control block, stale `7.3.N` auth-flow block, or missing `Security assessment` / `Relevant findings` labels | yes | rewrite `.fragments/security-architecture.md` |
| Any `__mermaid__ syntax error` detected in the rendered MD | yes | rewrite the fragment that contains the broken diagram |
