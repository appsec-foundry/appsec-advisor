#!/usr/bin/env bash
# auto_emitter_pass.sh — extracted VERBATIM from SKILL-impl.md (P3, 2026-06-20).
#
# The Auto-emitter pass was a 139-line inline Bash block in the skill body. It is
# pure orchestration (a fixed sequence of deterministic python emitters, each
# best-effort `|| true`), so it lifts 1:1 into a script with no behaviour change —
# removing the most error-prone class of inline shell from the resident skill body.
#
# Usage (called from SKILL-impl.md, AFTER the YAML integrity gate, AFTER the
# Stage-2 no-op gate, BEFORE the Stage-2 fragment pre-generator):
#
#   bash "$CLAUDE_PLUGIN_ROOT/scripts/auto_emitter_pass.sh" \
#       "$OUTPUT_DIR" "$REPO_ROOT" "$CLAUDE_PLUGIN_ROOT" "$DRY_RUN"
#
# Args:  $1 OUTPUT_DIR  $2 REPO_ROOT  $3 CLAUDE_PLUGIN_ROOT  $4 DRY_RUN(true|false)
#
# Contract preserved from the inline version: idempotent + best-effort — any
# emitter failure falls back to the pre-script YAML rather than aborting the run
# after 25+ minutes of Stage 1. NOT re-run inside the Re-Render Loop.
set -u

OUTPUT_DIR="${1:?OUTPUT_DIR required}"
REPO_ROOT="${2:?REPO_ROOT required}"
CLAUDE_PLUGIN_ROOT="${3:?CLAUDE_PLUGIN_ROOT required}"
DRY_RUN="${4:-false}"

# Auto-emitter pass — Meta-Findings + Review-Mitigations (M-RCA-2026-05) +
# deterministic YAML hygiene (M-RCA-2026-05b: sanitize_perimeter_claims,
# validate_evidence_lines, reclassify_components). Order matters:
#   1. emit_meta_findings   — derives MF-NNN from threats[] by source.
#   2. emit_review_mitigations — synthesises kind:review/investigate mitigations.
#   3. sanitize_perimeter_claims — strips speculative WAF/DDoS/firewall
#      absence phrasing from trust_boundaries[].enforcement and
#      security_controls[].notes. Runs BEFORE pre-gen so the deterministic
#      architecture-diagrams.md fragment inherits clean text.
#   4. validate_evidence_lines — deterministic floor for the
#      appsec-evidence-verifier agent. Sets evidence_check + evidence_flags
#      on every threat where the LLM verifier did not already write a
#      verified/refuted/verified-prior verdict.
#   5. reclassify_components — fixes attack-target-tier vs control-location-
#      tier drift. Reassigns threats whose evidence.file matches exactly
#      one other component's paths globs.
#   6. enforce_control_taxonomy — RC-1 + RC-6 (2026-05): canonicalises
#      security_controls[].control names (e.g. "JWT RS256 Authentication"
#      → "JWT Bearer Authentication") and re-routes mis-classified
#      security_controls[].domain entries (e.g. auth-flow rate limiting
#      parked in §7.12 Real-time → §7.2 IAM). Must run BEFORE
#      pregenerate_fragments so the mechanical §7.1 overview table +
#      `**Controls covered:**` lines are built from a taxonomy-clean yaml.
# All scripts are idempotent + best-effort: failures fall back to the
# pre-script YAML rather than aborting the run after 25+ minutes of Stage 1.
if [ "$DRY_RUN" = "false" ]; then
  {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  AUTO_EMITTER_START  meta-findings + review-mitigations + config-scan-mitigations + yaml-hygiene + vektors + open-registration + asset-links + control-taxonomy"
    # G1 (2026-07-05) — degenerate-evidence-verification guard. MUST run BEFORE
    # emit_review_mitigations: a too-weak verifier model can stamp every sampled
    # finding "ambiguous" (0 verified / 0 refuted), which otherwise cascades into
    # an all-review, no-P1 Mitigation Register (see the script docstring). When
    # the distribution is degenerate this strips evidence_check so the run is
    # treated as unverified-neutral; emit_review then emits no review cards,
    # emit_finding_fix produces real P1 fixes, and validate_evidence_lines (step
    # 4 below) re-derives per-line verdicts deterministically for §8.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/guard_evidence_verification.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_meta_findings.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_review_mitigations.py" "$OUTPUT_DIR" 2>&1 || true
    # M-RCA-2026-05 — `kind: fix` mitigations for config-scan threats.
    # Stage 1's appsec-config-scanner emits findings without remediation
    # prose (the agent's actual output schema is leaner than its docs imply)
    # and merge_threats._config_finding_to_threat does not populate
    # `mitigation_ids[]` or `remediation`. As a result, build_mitigations
    # never produced an M-NNN card for them and the §8 Threat Register
    # shipped with empty **Fix:** cells on every config-scan row. This
    # emitter looks up canonical remediation prose (config-iac-checks.yaml
    # by `config_check_id` → built-in slug map for scanner-synthesised
    # checks → generic fallback), allocates a new M-NNN per threat, and
    # links it back via threats[].mitigation_ids. Idempotent: prior
    # auto_source="config-scan" cards are cleared before re-computing.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_config_scan_mitigations.py" "$OUTPUT_DIR" 2>&1 || true
    # M-RCA-2026-06 — `kind: fix` mitigations for CODE findings the LLM left
    # uncovered. build_mitigations only emits an M-NNN card when the threat
    # already carries mitigation_ids[]; when Phase-11's LLM yaml-write
    # under-produces (2026-06-02 juice-shop: all 13 Critical findings came
    # back with mitigation_ids=[]), the Mitigation Register ships
    # "_No P1 mitigations._" despite every threat carrying a full remediation
    # block. This emitter backfills a fix card (priority from severity+effort)
    # for any non-config-scan threat with remediation content but no link, and
    # back-references it via threats[].mitigation_ids. Idempotent; runs AFTER
    # emit_config_scan_mitigations so config-scan threats are already linked
    # and skipped.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_finding_fix_mitigations.py" "$OUTPUT_DIR" 2>&1 || true
    # Clean finding TITLES (2026-06-12) — normalize threats[].title to
    # `<weakness class> — <file:line>` (strip `via <impl>`, parens, params,
    # embedded files). The verbose code-laden titles otherwise render into every
    # xref cell (§2/§4/§2.3/§8). Idempotent (_title_source). Runs before the
    # mitigation-title pass (independent; that keys on CWE, not title).
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_clean_finding_titles.py" "$OUTPUT_DIR" 2>&1 || true
    # General mitigation TITLES (2026-06-12) — runs AFTER all mitigation
    # emitters so it generalizes the full set. Stage 1 authors detailed
    # remediation instructions as mitigation_title ("Replace `.decode(token)`
    # with `.verify(...)`…", "Add HEALTHCHECK CMD curl -f http://…"); this
    # rewrites the §10 register/index TITLE to a clear class-level label keyed
    # on the addressed CWE (the actionable detail stays in the block body's
    # How/steps/code). Idempotent (stashes _title_source).
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_general_mitigation_titles.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/sanitize_perimeter_claims.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_evidence_lines.py" "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/reclassify_components.py" "$OUTPUT_DIR" 2>&1 || true
    # RC-1 + RC-6 (2026-05): canonicalise security_controls[].control names
    # against forbidden_heading_patterns + alias rewrites, and re-route
    # security_controls[].domain when token-match against a §7 method_whitelist
    # contradicts the Stage-1 assignment (specifically: auth controls parked
    # in §7.12 Real-time and Not Applicable Controls). Closes the cascade
    # of §7.2.1 heading-rename / §7.1 overview-table inconsistencies that
    # surfaced in the 2026-05-23 juice-shop run. Idempotent.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/enforce_control_taxonomy.py" "$OUTPUT_DIR" 2>&1 || true
    # Auth-coverage completeness (2026-06-06): §7.2 must ALWAYS identify,
    # describe and rate every authentication variant the app exposes — password
    # login, MFA, social/OAuth login — plus the password-credential lifecycle
    # (user registration, password reset). The Phase-8 analyst routinely omits
    # variants that exist in code (juice-shop: OAuth, registration, reset all
    # present, two anchoring Critical findings, none cataloged → §7.2 listed
    # only Password + MFA). This emitter backfills any DETECTED-but-uncataloged
    # canonical auth mechanism into security_controls[] with kind:mechanism (so
    # §7 renders a flow sub-block + sequenceDiagram) rated from its linked
    # finding(s), and records a lifecycle-required aspect (registration / reset)
    # that is genuinely absent under password auth as effectiveness:Missing.
    # Runs AFTER enforce_control_taxonomy (so the coverage check sees canonical
    # control names) and BEFORE pregenerate_fragments. Idempotent.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_auth_coverage.py" "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1 || true
    # Issue-1: deterministic vektor field per threat (CWE + attack_surface
    # auth_required → repo-read / victim-required / internet-anon /
    # internet-user) so §8 Vektor column reflects real reachability rather
    # than the renderer's `"internet-user"` default. Idempotent — preserves
    # any hand-set values.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_threat_vektors.py" "$OUTPUT_DIR" 2>&1 || true
    # Surface WHY a rating sits above its class baseline (public-repo secret,
    # unauth privileged endpoint, attack-chain keystone) as a short inline
    # severity_rationale the §8 card renders. Runs AFTER emit_threat_vektors
    # because the rationale keys on threats[].vektor. Idempotent.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_severity_rationale.py" "$OUTPUT_DIR" 2>&1 || true
    # Issue-1: detect open user self-registration; sets
    # meta.open_user_registration which the §6 heatmap renderer reads to
    # collapse internet-user / internet-priv-user actor cards into
    # internet-anon (registration is one POST away, the spectrum is
    # misleading on the at-a-glance view).
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/detect_open_registration.py" "$OUTPUT_DIR" 2>&1 || true
    # Public-repo detection (2026-06): sets meta.public_source_repo only on
    # high-confidence LOCAL signals (OSI license file + public-host github/
    # gitlab/bitbucket source URL). When true, compose collapses the repo-read
    # actor "Internal Developer" into "Anonymous Internet Attacker" (a public
    # repo's committed secrets are readable by anyone). When the evidence is
    # insufficient the flag is left UNSET and the Internal Developer actor is
    # kept — never guess public on a repo we cannot confirm. Honors the operator
    # override meta.public_source_repo_pinned. Needs --repo-root.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/detect_public_repo.py" "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1 || true
    # R-3 (2026-05): rebuild assets[].linked_threats from CWE-class affinity +
    # keyword overlap. Stage 1 Phase 5 is LLM-authored and routinely produces
    # links that have nothing to do with the asset (e.g. session-tokens linked
    # to YAML bomb / CORS / mass assignment instead of XSS + JWT storage).
    # Idempotent. Hand-set entries preserved via assets[].linked_threats_manual.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/enrich_asset_links.py" "$OUTPUT_DIR" 2>&1 || true
    # Mask committed secrets in Stage-1 evidence excerpts (e.g. raw
    # `password: 'admin123'`, PEM private-key markers) so the Stage-3
    # unmasked_secrets gate — which scans threat-model.yaml as well as the
    # rendered markdown — cannot trip on author-supplied excerpts. Uses the
    # SAME secret_scan.py pattern set as the gate, so detector⇔masker symmetry
    # guarantees the yaml passes. The composer applies the identical mask to the
    # rendered markdown (it re-reads real source files for §8 evidence), so both
    # artifacts are clean by construction. Idempotent and best-effort.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/secret_scan.py" --mask "$OUTPUT_DIR/threat-model.yaml" 2>&1 || true
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  AUTO_EMITTER_END"
  } | tee -a "$OUTPUT_DIR/.agent-run.log" >&2
fi
