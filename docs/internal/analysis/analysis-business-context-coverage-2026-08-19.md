# Business context: coverage, effects, and low-risk integration — 2026-08-19

Status: verified against the current pipeline. The low-risk ranking integration
described below is implemented.

## Conclusion

Business context already reached each STRIDE analyzer through a bounded
per-component projection, but most of its effect was prompt-level and difficult to
observe. Adding another LLM phase would duplicate context, increase cost, and make
the result harder to verify. The appropriate first change was deterministic:
material mapped context now breaks exact technical ranking ties for findings and
mitigations.

This is deliberately a small effect. Business context does not create findings,
change severity, change mitigation priority, override severity caps, or outrank a
higher technical score.

## End-to-end path

1. `scripts/load_business_context.py` captures either persistent
   `docs/business-context.md` or run-only `.business-context-input.md`. A supplied
   source is capped at 64 KiB, scanned for credentials, and recorded with
   provenance.
2. `scripts/build_threat_modeling_context.py` includes the effective source as
   fenced untrusted data in `.threat-modeling-context.md`, limited to 200 lines.
3. The `control_analyst` is the only analysis agent that receives project and
   optional organization business context. It maps relevant facts onto known
   component IDs in `.stride-analyst-context.json` as `business_purpose`,
   `impact_if_compromised`, `sensitive_assets`, `security_obligations`, and
   `security_assumptions`.
4. `scripts/build_stride_evidence_bundles.py` emits the component projection as
   `.dispatch-context/<component>/business-context.json`. Receipt and fingerprint
   checks reject stale or mismatched dispatch context.
5. Each STRIDE analyzer receives only its component projection. Shared context is
   not routed directly to STRIDE, merge, triage, or trust-boundary agents.
6. `scripts/triage_compute_ranking.py` now consumes the validated component map
   after analysis and uses only the presence of material mapped fields as a final
   deterministic tie-break.

The new behavior therefore applies only when an effective context source exists
and the control analyst maps at least one material field to the finding's
component. Missing, malformed, or empty optional context preserves the previous
ranking.

## What business context changes

### STRIDE scope and depth

Named `sensitive_assets` make a component a crown jewel for standard and thorough
scope and protect it from operational ceiling drops. They do not force full-depth
STRIDE: crown jewels remain eligible for cheap STRIDE when no independent role or
surface anchor exempts them. Quick mode may still omit a proven-internal crown
jewel.

Authentication, internet exposure, data-store roles, and similar depth anchors
come from architecture and source-derived component classification. A sentence in
business context saying that a component performs authentication does not itself
reclassify the component as an authentication component.

The STRIDE prompt already states that component business context informs impact.
This remains an LLM judgment and has no deterministic scale or automatic severity
lift.

### Rating review

`scripts/triage_validate_ratings.py` emits an informational review flag when a
Low-impact finding belongs to a component with declared compromise harm or
sensitive assets. The flag is skipped in quick mode, proposes no rating, and
leaves severity caps authoritative.

### Finding and mitigation ranking

The implemented integration uses `impact_if_compromised`, `sensitive_assets`, and
`security_obligations`. `business_purpose` and `security_assumptions` remain
descriptive and do not affect order.

- Between findings with the same technical score, a finding with material mapped
  context is listed first.
- A mitigation inherits business relevance only through the finding IDs it
  addresses. It moves first only when addressed severity and effort produce the
  same mitigation score.
- The structured ranking records the contributing field names and affected
  finding IDs. It never copies the business text into the ranking artifact.
- Higher technical scores always win. Severity, impact, likelihood, P1-P4
  priority, CVSS, and mitigation effort are unchanged.

This improves the order in which equal technical risks and actions are presented.
It does not improve the control analyst's mapping: an omitted or incorrect
component association remains omitted or incorrect.

## Corrections to the initial analysis

Two earlier conclusions were too strong:

- The prior business-context digest is read by `scripts/resolve_config.py` during
  incremental configuration. A changed or missing effective source produces a
  recommendation to run a full scan. The remaining observability gap is a
  declared context that maps to zero components, not absent digest comparison.
- Named sensitive assets do not necessarily receive full-depth STRIDE. They
  preserve standard/thorough scope and ceiling protection, while cheap STRIDE is
  intentionally selected by independent role and reachability rules.

## Remaining gaps and recommended order

1. **High value, low model cost:** expose the effective context source in the
   generated system-overview fragment and emit a run issue when declared context
   maps to zero components. Both can be deterministic and add no model calls.
2. **Medium risk:** make declared assets visible in the report's asset inventory.
   This changes report structure and requires an atomic producer, schema,
   renderer, QA, and test update.
3. **Defer:** add a separate LLM enrichment or verification phase only after an
   evaluation shows recurring mapping failures. A new phase should be conditional
   on effective context and should produce a small validated correction artifact,
   not rewrite findings or ratings.

The generated system-overview currently does not reproduce the context-source
disclosure still requested by the legacy report prompt. The deterministic
generator owns that fragment, so changing the prompt alone cannot fix the report.

The source builder also calls `_bounded_lines`, which reads a file fully before
applying its line limit. Captured `--context` input is size-capped, but a manually
created repository `docs/business-context.md` can bypass that capture-time cap.
This is a pre-existing resource-bound gap; replace the full read with a bounded
streaming read in a separate change.

## Token and risk assessment

The implemented change adds zero LLM calls and zero prompt or completion tokens.
Its runtime cost is one local JSON read plus small field-name arrays in the triage
artifact. The raw business prose is not duplicated.

The principal residual risk is incorrect component mapping. Restricting the
effect to exact score ties bounds that risk: bad context can reorder technically
equal items but cannot promote a weaker finding over a stronger one. Schema
validation restricts provenance to the three allowed fields, and absent or
malformed context falls back to the established technical order.

A separate LLM phase would add another full or partially cached context pass. The
exact token cost depends on the model and repository, but it would be materially
higher than the deterministic change and would add a second interpretation point.
It is not justified without measured evidence that the existing control-analyst
projection is inadequate.

## Verification

Tests cover exact-tie promotion, non-override of a higher technical score,
mitigation propagation through addressed finding IDs, provenance deduplication,
schema acceptance, schema rejection of non-material fields, and non-copying of
raw business prose. Targeted ranking, triage, dispatch, schema, and intermediate
validation tests pass. Repository-wide gate results and any unrelated baseline
failures are recorded with the implementation handoff.
