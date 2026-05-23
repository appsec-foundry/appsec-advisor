# Architect rating-coherence rules (D1 / D2 / D3 / D4)

Used by `appsec-architect-reviewer` Check 10 (Multi-Dimensional Rating Coherence). Each violation produces a `warning: coherence_<dim>_<propname>` or `info: coherence_<dim>_<propname>` finding.

## D1 — Intra-finding coherence

Per finding, check the following must-hold propositions; emit `warning: coherence_D1_<propname>` on violation:

| Proposition | Violation |
|---|---|
| `effective_severity >= raw risk` | effective lower than raw (only acceptable via explicit downgrade-flag in triage-flags) |
| If `effective_severity == Critical` AND `breach_distance == 3` → finding must be a keystone in an active chain with severity=Critical OR have `architectural_violation=true` | missing justification |
| If `chain_role == contributor` → `effective_severity ≤ High` | contributor rated Critical |
| If primary CWE ∈ `critical-criteria.yaml → never_individual_critical` AND `effective_severity == Critical` → finding MUST be keystone with `is_direct == True` | over-inflation flagged |
| If primary CWE ∈ `critical-criteria.yaml → always_critical_cwes` AND context matched AND `effective_severity < Critical` | under-rated |
| If primary CWE ∈ `severity-caps.yaml → severity_caps` AND `effective_severity > cap.max` | cap violation |
| `impact ≥ High` AND `likelihood == High` AND `breach_distance ≤ 2` → raw `risk` should be Critical | matrix says Critical but raw is lower |

## D2 — Cross-finding consistency

- Same `primary_cwe` in same `component` with abweichender `effective_severity` → `warning: coherence_D2_cross_drift`
- Same `finding_type_id` with ≥ 2-level severity spread (e.g. one Critical, one Medium) without explicit reason → `info: coherence_D2_type_drift`

## D3 — Compound-chain plausibility

Per active `compound_chain`:
- `chain.severity >= max(keystones.effective_severity)` → otherwise `warning: coherence_D3_chain_under_rated`
- `severity_justification` present AND non-empty AND contains at least one `because` / `since` / `due to` / `enables` / `requires` word → otherwise `info: coherence_D3_chain_justification_weak`
- All `keystones` belong to the same `chain.severity` tier or higher → if a keystone is Medium, `warning: coherence_D3_keystone_mismatch`

## D4 — CVSS ↔ qualitative band

Same rule as legacy Check 6 (band table in `shared/cvss-metrics.md`). Emit `warning: coherence_D4_cvss_band` on mismatch.
