#!/usr/bin/env python3
"""Resolve assessment flags into the run configuration.

``resolve_assessment()`` is the only entry point. The controller calls it once
per admitted scope and writes the result to ``$OUTPUT_DIR/.skill-config.json``
for downstream scripts. Each per-topic resolver (requirements, YAML, depth,
reasoning models, architect review, paths, business context) is a pure function
with unit tests. Invalid or conflicting flags raise ``SystemExit`` with the
reason.
"""

from __future__ import annotations

# Loading this file by path must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import re
import secrets
import subprocess
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Model matrix — mirrors SKILL.md "Reasoning Model Resolution → Mode matrix"
# ---------------------------------------------------------------------------


# Canonical reasoning tiers. ``haiku-economy`` was the original name for the
# economy tier, but it oversells the Haiku routing: STRIDE/triage/merger stay
# on Sonnet (see below). The honest name is ``sonnet-economy`` — a Sonnet
# reasoning floor with economy periphery. ``haiku-economy`` is retained as a
# backward-compatible input alias (CLI flags, stored .skill-config.json,
# recorded fixtures) and is normalised to the canonical name on the way in.
REASONING_ALIASES = {"haiku-economy": "sonnet-economy"}


def canonical_reasoning_model(mode):
    """Map a deprecated reasoning-tier alias to its canonical name.

    Pass-through for unknown / canonical values and for ``None``.
    """
    if mode is None:
        return mode
    return REASONING_ALIASES.get(mode, mode)


MODEL_MATRIX = {
    "sonnet": {
        "stride": "sonnet",
        "triage": "sonnet",
        "merger": "sonnet",
    },
    # opus-cheap: explicit opt-in only — no longer any depth's default since
    # 2026-06 (was the standard/thorough default). It puts Opus on the cheap
    # merger phase while leaving STRIDE — the value-creating reasoning — on
    # Sonnet, which is the inverse of where Opus pays off. Kept as a valid
    # --reasoning-model choice for a deliberate middle ground.
    "opus-cheap": {
        "stride": "sonnet",
        # triage stays on Sonnet: scripts/validators/triage_validate_ratings.py provides a
        # deterministic floor (outlier thresholds, completeness counts, CVSS
        # eligibility); the agent only does judgment-call validation on top.
        # Opus here was overkill — Sonnet handles the structured input.
        "triage": "sonnet",
        "merger": "opus",
    },
    "opus": {
        "stride": "opus",
        "triage": "opus",
        "merger": "opus",
    },
    # sonnet-economy: threat reasoning (STRIDE/triage/merger) stays on the
    # Sonnet TIER — it is NOT routed to Haiku (the principle: the main value
    # contributor must not be downgraded). The Haiku lever kicks in for the
    # more-deterministic agents via EXTENDED_MODEL_MATRIX (context-resolver,
    # recon-scanner, qa-routine, config-scanner). Quick mode additionally gets
    # a STRIDE depth reduction via resolve_stride_profile(). (Alias: haiku-economy.)
    #
    # COST PIN (2026-07-04): the concrete Sonnet is pinned here to ``claude-sonnet-4-6``
    # rather than the bare alias ``"sonnet"`` (→ now Sonnet 5). Reason: same
    # price/token, but the 4.6 tokenizer counts the same text in ~30% FEWER tokens
    # than Sonnet 5 (+ no adaptive thinking by default) → the subagent half of a
    # full scan drops from ~$60 back to the ~$37 level, without violating the
    # Sonnet-tier principle (4.6 IS Sonnet, just the previous version).
    # sonnet-economy is the default for quick/standard, so it applies automatically
    # for all plugin users. Opt in to Sonnet 5 (quality): ``--reasoning-model
    # sonnet``. Exact pin per stage: ``APPSEC_{STRIDE,TRIAGE,MERGER}_MODEL=…``.
    # Deprecation note: when claude-sonnet-4-6 is retired, bump it here.
    "sonnet-economy": {
        "stride": "claude-sonnet-4-6",
        "triage": "claude-sonnet-4-6",
        "merger": "claude-sonnet-4-6",
    },
}

# Routing for agents beyond stride/triage/merger.
# Key: (reasoning_tier, depth) → agent_type → model.
# Default routing applies for sonnet/opus-cheap/opus (= unchanged from today).
# sonnet-economy has depth-specific routing.
HAIKU = "haiku"
SONNET = "sonnet"
# Explicit latest-Sonnet pin used for the `standard` quality buy-back (2026-07-05):
# the aggregation/judgment stages measurably improve on Sonnet 5 (see
# docs/model-selection.md "Benchmarks"). Kept as an exact id, not the `sonnet`
# alias, so a headless run pins the version rather than following the session.
# The pin follows the latest Sonnet release; Sonnet 5.5 has no A/B of its own.
SONNET5 = "claude-sonnet-5-5"
# The economy pin; a combined assessment moves STRIDE off it (MD-9).
SONNET46 = "claude-sonnet-4-6"

EXTENDED_MODEL_MATRIX: dict[tuple[str, str], dict[str, str]] = {
    # sonnet-economy: extended-agent routing.
    #
    # context-resolver, recon-scanner, config-scanner are deterministic
    # tasks (extraction / grep / rule-engine application against a YAML
    # check catalog) — they run on Haiku at every depth.
    # qa_routine moves up to Sonnet at thorough because the document is
    # bigger and more cross-references need reconciling.
    ("sonnet-economy", "quick"): {
        "context_resolver": HAIKU,
        "recon_scanner": HAIKU,
        "qa_routine": HAIKU,
        "qa_content": SONNET,
        "config_scanner": HAIKU,
        "orchestrator": SONNET,
        # renderer + abuse_verifier follow the `sonnet` alias → host session at
        # every depth (no depth variation, like orchestrator). Manual pin via
        # APPSEC_RENDERER_MODEL / APPSEC_ABUSE_VERIFIER_MODEL for quality buy-back
        # (Sonnet-5) or cost (4.6) without moving the whole session.
        #
        # evidence_verifier stays on SONNET at every tier and depth — including
        # sonnet-economy, where every other extraction role drops to Haiku.
        # Verified/refuted/ambiguous discrimination requires reading code
        # semantics at the cited line; Haiku regressed to stamping every sampled
        # finding `ambiguous` (0 verified / 0 refuted, ~57ms batch), which
        # cascaded into an all-review, zero-P1 Mitigation Register. Override via
        # APPSEC_EVIDENCE_VERIFIER_MODEL only with that failure mode in mind.
        "renderer": SONNET,
        "abuse_verifier": SONNET,
        "evidence_verifier": SONNET,
    },
    ("sonnet-economy", "standard"): {
        "context_resolver": HAIKU,
        "recon_scanner": HAIKU,
        "qa_routine": HAIKU,
        "qa_content": SONNET,
        "config_scanner": HAIKU,
        "orchestrator": SONNET,
        "renderer": SONNET,
        "abuse_verifier": SONNET,
        "evidence_verifier": SONNET,
    },
    ("sonnet-economy", "thorough"): {
        "context_resolver": HAIKU,
        "recon_scanner": HAIKU,
        "qa_routine": SONNET,
        "qa_content": SONNET,
        "config_scanner": HAIKU,
        "orchestrator": SONNET,
        "renderer": SONNET,
        "abuse_verifier": SONNET,
        "evidence_verifier": SONNET,
    },
}

# Default routing for sonnet/opus-cheap/opus.
# Even on the default tiers, context-resolver, recon-scanner and
# config-scanner are routed to Haiku — these phases are pure extraction /
# grep / lookup-table application and need no Sonnet floor.
# To override, set APPSEC_RECON_SCANNER_MODEL etc.
_DEFAULT_EXTENDED_ROUTING = {
    "context_resolver": HAIKU,
    "recon_scanner": HAIKU,
    "qa_routine": SONNET,
    "qa_content": SONNET,
    "config_scanner": HAIKU,
    "orchestrator": SONNET,
    "renderer": SONNET,
    "abuse_verifier": SONNET,
    "evidence_verifier": SONNET,
}

# Quick-mode STRIDE depth reduction. The model stays Sonnet — only the
# task scope is reduced. Applies independently of the reasoning tier
# when assessment_depth == "quick".
#
# P3 (A6) re-balance: ``skip_evidence_excerpt`` was demoted from True to
# False. The evidence excerpt is a yaml-side string trim of the threat's
# ``scenario`` field — its emission costs the STRIDE analyzer nothing
# extra (the field is read by the renderer's ``_synthesise_label`` helper,
# not generated as new prose), and dropping it stripped the Linked-Threats
# columns and §8 Finding column of every descriptive substring. The
# remaining flags (skip_verification_greps, max_threats_per_category,
# skip_code_examples, skip_cvss_scoring, turn_budget_hard_cap) preserve
# the real token-budget reductions while the report regains its
# scannable-evidence content.
QUICK_STRIDE_PROFILE = {
    "skip_verification_greps": True,  # A
    "max_threats_per_category": 1,  # B (was 2 — quick is a triage pass.
    #     Keep only the top-severity threat
    #     per STRIDE category per component.
    #     CRITICAL/HIGH-SAFE: the analyzer never
    #     drops a Critical or High to honour this cap
    #     — see appsec-stride-analyzer-v2.md
    #     Quick-mode table exception.)
    "skip_code_examples": False,  # C (R9 — was True; flipped 2026-05.
    #     User feedback: mitigations without
    #     code hints are not actionable.
    #     Marginal cost ≈ 200-400 output
    #     tokens per mitigation × ~20
    #     mitigations ≈ <1 min added to a
    #     ~33-min Quick run. Real turn-
    #     budget savings come from A/B/E/F.)
    "skip_evidence_excerpt": False,  # D (P3 — was True; cheap to keep, restores §8 evidence)
    "skip_cvss_scoring": True,  # E
    "turn_budget_hard_cap": 25,  # F (was 40)
}

# NOTE: the per-depth STRIDE-component COUNT (formerly "components": 3/5/8) was
# removed 2026-06-07. The analyzed-component set is no longer a hard-coded number
# — it is derived from criteria (exposure / ci-cd / crown-jewel) by
# orchestrator/build_stride_dispatch_manifest.py:select_stride_components(). Depth changes only
# the STRIDE turn budget + diagram/QA depth here; WHICH components get analyzed is
# decided by the criteria predicate over the full inventory in .components.json.
DEPTH_PARAMS = {
    "quick": {
        "simple": 10,
        "moderate": 15,
        "complex": 20,
        "diagrams": "minimal",
        "qa": "core",
        "qa_label": "skipped",
        "max_repair_iterations": 1,
    },
    "standard": {
        "simple": 15,
        "moderate": 22,
        "complex": 31,
        "diagrams": "standard",
        "qa": "full",
        "qa_label": "full",
        "max_repair_iterations": 1,
    },
    "thorough": {
        "simple": 20,
        "moderate": 28,
        "complex": 35,
        "diagrams": "extended",
        "qa": "extended",
        "qa_label": "extended",
        "max_repair_iterations": 3,
    },
}

# Optional trust-boundary context is capped independently from the STRIDE turn
# budgets above.  The context preparer imports this constant; neither depth
# parameters nor the dispatch builder's fallback should duplicate it.
BOUNDARY_CANDIDATE_LIMITS = {"quick": 2, "standard": 4, "thorough": 6}
# ``max_repair_iterations`` — the hard cap on the Stage-3 QA / Stage-4 architect
# Re-Render Loop. At quick/standard the loop is a SINGLE quick-fix pass (one
# repair attempt, then fail-closed `exit 2` if the contract still does not hold —
# never ship an invalid report). thorough keeps the historical budget of 3.
# Consumed by skills/create-threat-model/SKILL-thin-stage3.md (the loop reads
# $MAX_REPAIR_ITERATIONS). NOTE: this key is intentionally NOT mirrored into
# build_stride_dispatch_manifest._FALLBACK_DEPTH_PARAMS — that fallback only
# tracks the per-complexity STRIDE turn budgets (simple/moderate/complex).

# Operational safety ceiling on the number of components dispatched to STRIDE —
# a merge/turn-budget guard, NOT the selection count. The criteria predicate is
# the selector; this only caps a pathologically large inventory (auth/frontend/
# exposed are never dropped — the ceiling lifts and logs EXPOSURE_CAP_LIFT).
# Depth-independent: the same operational limit regardless of assessment depth.
# Recon deliberately has no hard inventory cap. When positive selection
# criteria yield more than this ceiling (for example 50 exposed services), the
# ceiling lifts and bounded dispatch waves control execution pressure instead.
STRIDE_COMPONENT_CEILING = 10

# Maximum number of per-component STRIDE agents dispatched in one foreground
# wave. Selection remains uncapped for exposed/security-relevant components;
# this bounds only concurrent execution pressure. Override for a particular
# host with APPSEC_STRIDE_CONCURRENCY (1..5). The upper bound keeps one
# context-v2 wave within the 64-artifact immediate receipt-verification cap:
# bundle, component plan, optional business and architecture projections,
# optional repository projection, and six independently receipted component
# security projections, plus the effective-plan receipt.
STRIDE_DISPATCH_CONCURRENCY = 5
STRIDE_DISPATCH_CONCURRENCY_MAX = 5


# ---------------------------------------------------------------------------
# Conflict detection — runs before any resolution
# ---------------------------------------------------------------------------


CONFLICT_PAIRS: list[tuple[str, str, str]] = [
    # (attr_a, attr_b, error_message)
    ("yaml", "no_yaml", "--yaml and --no-yaml cannot be used together."),
    ("requirements", "no_requirements", "--requirements and --no-requirements cannot be used together."),
    ("full", "incremental", "--full and --incremental cannot be used together."),
    ("full", "resume", "--full starts a complete assessment; --resume continues a checkpoint. Pick one."),
    ("rebuild", "incremental", "--rebuild discards all prior state; --incremental requires it. Pick one."),
    ("rebuild", "resume", "--rebuild wipes the checkpoint file; --resume needs it. Pick one."),
    ("rerender", "full", "--rerender re-renders the existing assessment; --full rebuilds it. Pick one."),
    ("rerender", "incremental", "--rerender reuses Stage-1 outputs; --incremental re-analyzes a delta. Pick one."),
    ("rerender", "rebuild", "--rerender reuses existing artifacts; --rebuild wipes them. Pick one."),
    ("rerender", "resume", "--rerender starts a fresh render; --resume continues a checkpoint. Pick one."),
    ("context", "rerender", "--rerender re-renders an existing analysis; --context only affects a new one."),
    ("context", "resume", "--resume continues a run whose context was already resolved; --context comes too late."),
    (
        "architect_review",
        "no_architect_review",
        "--architect-review and --no-architect-review cannot be used together.",
    ),
    ("quick", "thorough", "--quick and --thorough cannot be used together."),
    ("enrich_arch", "no_enrich_arch", "--enrich-arch and --no-enrich-arch cannot be used together."),
    ("abuse_cases", "no_abuse_cases", "--abuse-cases and --no-abuse-cases cannot be used together."),
    (
        "abuse_case_file",
        "no_abuse_cases",
        "--abuse-case-file names cases to verify; --no-abuse-cases turns verification off. Pick one.",
    ),
    (
        "only_abuse_case",
        "no_abuse_cases",
        "--only-abuse-case selects cases to verify; --no-abuse-cases turns verification off. Pick one.",
    ),
    ("cheap_stride", "no_cheap_stride", "--cheap-stride and --no-cheap-stride cannot be used together."),
]


def detect_conflicts(ns: argparse.Namespace) -> Optional[str]:
    for a, b, msg in CONFLICT_PAIRS:
        if getattr(ns, a, False) and getattr(ns, b, False):
            return msg
    slug = getattr(ns, "slug", None)
    # "__auto__" is the bare-flag sentinel (random slug generated at resolve
    # time) — only an explicit user value is validated for filename-safety.
    if slug is not None and slug != "__auto__" and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", slug):
        return "--slug must be 1-64 filename-safe characters ([A-Za-z0-9._-]); got: " + repr(slug)
    # `--slug` takes an OPTIONAL value, so argparse refuses to consume a token
    # that starts with '-'. In `--slug --keep-runtime-files my-label` the label
    # therefore lands in the positional `scope` and the run silently stamps a
    # random slug instead — the user only finds out ~3 hours later, from the
    # filenames (juice-shop 2026-08-02: shipped as `threat-model-3225.*`).
    # Refuse the ambiguity instead of guessing: a lone filename-safe token next
    # to a bare `--slug` is a swallowed value, not a scope phrase (those are
    # prose, and read as several words).
    if slug == "__auto__":
        scope_words = [str(s) for s in (getattr(ns, "scope", None) or [])]
        if len(scope_words) == 1 and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", scope_words[0]):
            return (
                f"--slug was given no value, so {scope_words[0]!r} was read as scope and the "
                f"deliverables would be stamped with a random slug. Write the value directly "
                f"after the flag (--slug {scope_words[0]}), or drop the trailing argument to "
                f"keep the generated slug."
            )
    return None


# ---------------------------------------------------------------------------
# Per-resolver functions — each is pure, takes the namespace + external
# state, and returns a dict of resolved values to merge into the config.
# ---------------------------------------------------------------------------


def resolve_write_yaml(ns: argparse.Namespace) -> dict:
    if ns.no_yaml:
        return {"write_yaml": False, "write_yaml_label": "disabled (--no-yaml)"}
    if ns.yaml:
        return {"write_yaml": True, "write_yaml_label": "enabled (--yaml)"}
    return {"write_yaml": True, "write_yaml_label": "enabled (default)"}


def resolve_requirements(ns: argparse.Namespace, config_enabled: bool) -> dict:
    """Resolution order: --no-requirements → --requirements → config → false.

    A URL override attached to --requirements is also captured. Quick
    assessment depth flips the default to disabled unless the user
    explicitly opted in via --requirements.
    """
    if ns.no_requirements:
        return {
            "check_requirements": False,
            "requirements_url_override": None,
            "requirements_label": "disabled (--no-requirements)",
        }
    if ns.requirements is not None:
        return {
            "check_requirements": True,
            "requirements_url_override": ns.requirements or None,
            "requirements_label": (
                f"enabled (--requirements {ns.requirements})" if ns.requirements else "enabled (--requirements)"
            ),
        }
    if config_enabled:
        return {"check_requirements": True, "requirements_url_override": None, "requirements_label": "enabled (config)"}
    return {"check_requirements": False, "requirements_url_override": None, "requirements_label": "disabled (config)"}


def resolve_assessment_depth(ns: argparse.Namespace) -> dict:
    depth = ns.assessment_depth or "standard"
    params = DEPTH_PARAMS[depth]
    label = (
        f"{depth} (components: criteria-selected, STRIDE turns: "
        f"{params['simple']}/{params['moderate']}/{params['complex']}, "
        f"diagrams: {params['diagrams']}, QA: {params['qa_label']})"
    )
    return {
        "assessment_depth": depth,
        "max_stride_components": STRIDE_COMPONENT_CEILING,
        "max_boundary_candidates_per_component": BOUNDARY_CANDIDATE_LIMITS[depth],
        "stride_turns_simple": params["simple"],
        "stride_turns_moderate": params["moderate"],
        "stride_turns_complex": params["complex"],
        "diagram_depth": params["diagrams"],
        "qa_depth": params["qa"],
        "max_repair_iterations": params["max_repair_iterations"],
        "depth_label": label,
        # Severity floor for the canonical register (2026-06-26). Default
        # 'medium' drops Low/Informational — low-risk findings are noise in a
        # threat model. Override with --register-severity-floor low to keep them.
        "register_severity_floor": (getattr(ns, "register_severity_floor", None) or "medium"),
    }


def resolve_stride_concurrency() -> dict:
    raw = os.environ.get("APPSEC_STRIDE_CONCURRENCY")
    if raw is None or not raw.strip():
        return {"stride_concurrency": STRIDE_DISPATCH_CONCURRENCY}
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(
            f"Error: APPSEC_STRIDE_CONCURRENCY must be an integer between 1 and {STRIDE_DISPATCH_CONCURRENCY_MAX}"
        ) from exc
    if not 1 <= value <= STRIDE_DISPATCH_CONCURRENCY_MAX:
        raise SystemExit(f"Error: APPSEC_STRIDE_CONCURRENCY must be between 1 and {STRIDE_DISPATCH_CONCURRENCY_MAX}")
    return {"stride_concurrency": value}


# Artifact contracts a context-v2 run reconstructs its successor action from.
# Persisted with the run so a resume can prove the on-disk artifacts still match
# the producer that wrote them instead of re-deriving the answer from the
# current environment.
CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS = {
    "orchestration-action": 1,
    "route-inventory": 1,
    "recon-patterns": 1,
    "recon-summary-context": 1,
    "architecture-route-context": 1,
    "recon-signals": 2,
    "actors-merged-static": 1,
    "actors-resolved": 1,
    "trust-boundary-assessment-input": 1,
    "trust-boundaries": 2,
    "stride-analyst-context": 1,
    "stride-dispatch-manifest": 2,
    "stride-dispatch-waves": 2,
    "stride-evidence-bundle": 1,
    "stride-component-context-plan": 1,
    "stride-component-business-context": 1,
    "stride-component-architecture-context": 1,
    "stride-component-security-context": 1,
    "stride-component-repository-roots": 1,
    "stride-repository-registry": 1,
    "context-effective-plan": 1,
    "context-effective-plan-receipt": 1,
    "merge-candidates": 1,
    "merge-review-context": 1,
    "merge-decisions": 2,
    "threats-merged": 1,
    "evidence-verification": 1,
    "evidence-verifier-context": 1,
    "post-stride-generated-threats": 1,
    "post-stride-proposed-mitigations": 1,
    "abuse-case-verifier-context": 1,
    "abuse-case-deriver-context": 1,
    "triage-flags": 2,
    "mitigation-overrides": 1,
    "tier-root-causes": 1,
}


def resolve_runtime_generation() -> dict:
    """Return the sole producer generation for every new invocation.

    Runtime support is decided by the controller before it mutates run state.
    Persisting one generation even for a rejected configuration makes it
    impossible for an environment override or a special mode to revive the
    removed producer.
    """
    return {
        "runtime_generation": "context-v2",
        "runtime_generation_label": "context-v2 (single runtime)",
        "runtime_artifact_schema_versions": dict(CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS),
    }


def resolve_evidence_verifier_cap(ns: argparse.Namespace, depth: str) -> dict:
    """Bound Phase 10a work while preserving every Critical finding.

    The verifier prompt applies this cap *after* selecting all Criticals, so a
    repository with more Criticals than the configured cap still verifies each
    of them.  The default keeps normal standard runs bounded without reducing
    the high-risk coverage that makes the phase useful.
    """
    requested = getattr(ns, "evidence_verifier_cap", None)
    if requested is not None:
        return {
            "evidence_verifier_max_findings": requested,
            "evidence_verifier_cap_label": f"{requested} (--evidence-verifier-cap)",
        }
    defaults = {"quick": 20, "standard": 30, "thorough": 100}
    cap = defaults[depth]
    return {
        "evidence_verifier_max_findings": cap,
        "evidence_verifier_cap_label": f"{cap} (depth default)",
    }


def resolve_abuse_case_verification(ns: argparse.Namespace, depth: str) -> dict:
    """Resolve ``skip_abuse_case_verification`` + a human-readable label.

    Default: abuse-case verification runs at standard/thorough and is SKIPPED
    at quick depth — the fast mode drops the per-candidate verifier fan-out
    (matcher + haiku/sonnet verifiers + chain fold), the most expensive part of
    Stage 1d. ``--abuse-cases`` forces it on at any depth (incl. quick);
    ``--no-abuse-cases`` forces it off at any depth (incl. standard/thorough).
    ``--abuse-case-file`` / ``--only-abuse-case`` name the cases this run is to
    verify, so they force it on the same way — otherwise the named cases would
    be resolved into a stage that never runs. Conflicting combinations are
    rejected up front (see ``CONFLICT_PAIRS``).
    """
    if getattr(ns, "no_abuse_cases", False):
        return {"skip_abuse_case_verification": True, "abuse_case_label": "skipped (--no-abuse-cases)"}
    if getattr(ns, "abuse_cases", False):
        return {"skip_abuse_case_verification": False, "abuse_case_label": "enabled (--abuse-cases)"}
    if getattr(ns, "abuse_case_file", None) or getattr(ns, "only_abuse_case", None):
        return {
            "skip_abuse_case_verification": False,
            "abuse_case_label": "enabled (per-scan case selection)",
        }
    if depth == "quick":
        return {"skip_abuse_case_verification": True, "abuse_case_label": "skipped (auto - quick depth)"}
    return {"skip_abuse_case_verification": False, "abuse_case_label": "enabled"}


def resolve_cheap_stride(ns: argparse.Namespace, depth: str) -> dict:
    """Resolve ``cheap_stride`` + a human-readable label.

    Default: ON at quick and standard depth, OFF at thorough. Screening depth is
    a cost/pacing tier for components that are *proven* side-of-the-house, and
    ``build_stride_dispatch_manifest._cheap_stride_target`` is what decides that:
    auth, frontend, LLM, internet-exposed, file-upload, realtime, data-store and
    core-backend components always keep full depth, and so does anything whose
    reachability is unknown. Only ci-cd and provably-internal components qualify,
    which is why this is safe to default — it can only ever trim the tail.
    Thorough keeps full depth everywhere by definition: it is the mode a user
    picks when depth matters more than cost.

    ``--cheap-stride`` forces it on at any depth (incl. thorough);
    ``--no-cheap-stride`` forces it off at any depth. The two flags are mutually
    exclusive (see ``CONFLICT_PAIRS``).
    """
    if getattr(ns, "no_cheap_stride", False):
        return {"cheap_stride": False, "cheap_stride_label": "off (--no-cheap-stride)"}
    if getattr(ns, "cheap_stride", False):
        return {"cheap_stride": True, "cheap_stride_label": "on (--cheap-stride)"}
    if depth == "thorough":
        return {"cheap_stride": False, "cheap_stride_label": "off (auto - thorough depth)"}
    return {"cheap_stride": True, "cheap_stride_label": f"on (auto - {depth} depth)"}


# B2c — repo-size auto-cap thresholds.
# Source: 2026-04-27 juice-shop incident — 5 STRIDE components once consumed
# 50+ min in Phase 9 on cold caches and never finished, so large repos were
# capped to 3 components. 2026-06-02 reversal: dropping components is the WRONG
# cost/time lever — it created whole-component BLIND SPOTS (the 2026-06-02
# cap-to-3 run missed the b2b-api RCE and the data-tier entirely, 23 threats vs
# 42, and never even catalogued the §7.2 MFA surface). On large repos we now
# keep the default reasoning tier (Opus on STRIDE/triage/merger — large repos
# are where Opus pays off; the B2d economy auto-downgrade was removed 2026-06)
# and analyze ALL components — the Phase-9 heartbeat watchdog
# (runtime/skill_watchdog.py: stride-stale 900s, per-component
# timeout 480s) bounds any cold-cache hang instead of pre-emptively dropping
# attack surface. Cost is controlled by the tier, not by blind spots.
# User-facing text derived from this threshold states RUNTIME ("longer run
# expected"), never repo SIZE. Size is judged on one axis only — the much higher
# orchestrator-window threshold below — otherwise the pre-flight box contradicts
# itself (a 650-file repo is "normal-sized" there and would read "large" here).
LARGE_REPO_SOURCE_FILE_THRESHOLD = 400

# Orchestrator (session-model) recommendation threshold — DISTINCT from and much
# higher than LARGE_REPO_SOURCE_FILE_THRESHOLD above (which only flags "longer run").
# The orchestrator holds the largest resident context; on a *very* large repo a
# small-window session model (Sonnet 4.6 in the harness) risks mid-run compaction,
# which can drop finalization steps. At/above this source-file count we RECOMMEND the
# large-window Sonnet 5 as the SESSION model (higher cost, for more compaction
# headroom); below it we recommend Sonnet 4.6 (much cheaper, only very limited
# orchestrator benefit). Advisory only — the user always chooses (see the
# interactive prompt in the compact full runtime).
# CALIBRATION CAVEAT: this is a coarse heuristic, not a measured compaction point.
# We have one calibration repo (Juice-Shop, ~650 source files by the count below);
# 2500 is simply a margin well above it so a normal app recommends 4.6. Source-file
# count is a *proxy* — the orchestrator's resident context is really driven by the
# analyzed component count and finding volume (roughly bounded, not linear in files),
# so the true compaction point does not track this number precisely. Kept because it
# is the only cheap signal available pre-recon, and the recommendation is fail-safe
# (defaults to the cheap model, user overrides).
ORCHESTRATOR_SONNET5_FILE_THRESHOLD = 2500
SOURCE_FILE_EXTENSIONS = (
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".go",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".swift",
    ".scala",
    ".cpp",
    ".c",
    ".h",
)


def _count_source_files(repo_root: Path) -> int:
    """Count tracked source files via git ls-files. Returns 0 on any error.

    Cheap (one subprocess) and bounded (timeout 5 s). Falls back to 0 — which
    skips the cap heuristic — rather than failing the resolution.
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode != 0:
            return 0
        count = 0
        for line in r.stdout.splitlines():
            if line.endswith(SOURCE_FILE_EXTENSIONS):
                count += 1
        return count
    except (OSError, subprocess.SubprocessError):
        return 0


def resolve_repo_size_cap(cfg: dict, repo_root: Path, *, source_count: int | None = None) -> dict:
    """B2c — flag large standard-depth repos (informational only).

    Triggers only when:
      * assessment_depth is "standard" (the default tier — so the user did
        not explicitly opt for a deeper analysis)
      * source-file count > LARGE_REPO_SOURCE_FILE_THRESHOLD
      * the user did not pass --assessment-depth thorough explicitly

    On trigger: set repo_size_capped=True and append a marker to depth_label.
    No component count is reduced — the analyzed set is criteria-derived
    (2026-06-07). Since 2026-06 the flag is **purely informational** (a
    "large repo → longer run" heads-up); it no longer downgrades the reasoning
    tier (the B2d auto-downgrade was removed — large repos are where Opus
    reasoning pays off).

    Returns the patched cfg slice (dict — not the full cfg) so the caller
    can `cfg.update(...)` it.
    """
    if cfg.get("assessment_depth") != "standard":
        return {}
    src_count = _count_source_files(repo_root) if source_count is None else source_count
    if src_count <= LARGE_REPO_SOURCE_FILE_THRESHOLD:
        return {}
    # Large repo: flag it (informational). We do NOT drop components —
    # dropping creates whole-component blind spots (2026-06-02); since
    # 2026-06-07 the analyzed set is criteria-derived, not a number, so there
    # is no component count to reduce here. Since 2026-06 the flag no longer
    # downgrades the reasoning tier either (B2d removed) — it is purely a
    # "large repo → longer run" heads-up.
    new_label = (
        f"{cfg['assessment_depth']} (criteria-selected components — "
        f"{src_count} source files → longer run expected, "
        f"reasoning on default tier, "
        f"STRIDE turns: {cfg['stride_turns_simple']}/"
        f"{cfg['stride_turns_moderate']}/{cfg['stride_turns_complex']}, "
        f"diagrams: {cfg['diagram_depth']}, QA: {cfg['qa_depth']})"
    )
    return {
        "depth_label": new_label,
        "repo_size_capped": True,
        "repo_size_source_files": src_count,
    }


def recommend_orchestrator_model(src_count: int) -> dict:
    """Advisory session-model recommendation from repo source-file count.

    The orchestrator = the CC session model; the plugin cannot switch it. This
    only RECOMMENDS — the skill surfaces it and the user chooses (a divergent
    choice needs a session restart because a running loop cannot change its own
    model). Recommends Sonnet 5.5 only for *very* large repos (window safety);
    otherwise Sonnet 4.6 (much cheaper, only very limited orchestrator benefit).
    """
    if src_count >= ORCHESTRATOR_SONNET5_FILE_THRESHOLD:
        model = SONNET5
        reason = (
            f"very large repo ({src_count} source files >= "
            f"{ORCHESTRATOR_SONNET5_FILE_THRESHOLD}) — the orchestrator accumulates a "
            f"large resident context; Sonnet 5.5's larger window reduces the risk of "
            f"mid-run compaction (higher cost). Note: this is a coarse file-count "
            f"heuristic — a margin above our single calibration repo, not a measured "
            f"compaction threshold"
        )
    else:
        model = "claude-sonnet-4-6"
        reason = (
            f"normal-sized repo ({src_count} source files < "
            f"{ORCHESTRATOR_SONNET5_FILE_THRESHOLD}) — Sonnet 4.6 as the session model "
            f"has significantly lower cost than a Sonnet-5 or Opus session, which "
            f"bring only very limited benefit on the orchestrator role at this repo "
            f"size, and its window is sufficient here (Sonnet 5.5 is recommended once a "
            f"repo crosses {ORCHESTRATOR_SONNET5_FILE_THRESHOLD} files)"
        )
    return {
        "orchestrator_recommended_model": model,
        "orchestrator_recommendation_reason": reason,
        "orchestrator_recommendation_repo_files": src_count,
    }


def resolve_reasoning_model(ns: argparse.Namespace, depth: str) -> dict:
    """Resolution order: env-vars → --reasoning-model → depth default.

    Defaults per depth:
      • quick    → sonnet-economy (deterministic-leaning agents on Haiku;
                   Reasoning core stays on Sonnet)
      • standard → sonnet-economy (the everyday default — favour cost;
                   Reasoning core on Sonnet)
      • thorough → opus  (premium tier: STRIDE/triage/merger on Opus)

    Override with ``--reasoning-model sonnet`` to keep all agents on
    Sonnet at quick (pre-2026-05 behaviour). Env vars
    (APPSEC_STRIDE_MODEL / APPSEC_TRIAGE_MODEL / APPSEC_MERGER_MODEL)
    take highest precedence for fine-grained overrides.

    The ``sonnet-economy`` tier keeps STRIDE/triage/merger on the Sonnet
    TIER (Threat-Reasoning is the tool's primary value contribution and
    must not be downgraded to Haiku). Since 2026-07-04 the concrete Sonnet
    is cost-pinned to ``claude-sonnet-4-6`` (same tier, ~30% fewer tokens
    than Sonnet 5 at equal per-token price — see the MODEL_MATRIX comment).
    Opt into Sonnet 5 with ``--reasoning-model sonnet``; pin an exact model
    per stage with ``APPSEC_{STRIDE,TRIAGE,MERGER}_MODEL``. The Haiku savings
    come from the deterministic-leaning agents (context-resolver,
    recon-scanner, qa-routine fixes, config-scanner) — see
    resolve_extended_models.
    """
    # Step 1: pick the base mode (normalising deprecated aliases).
    if ns.reasoning_model:
        mode = canonical_reasoning_model(ns.reasoning_model)
    elif depth in ("quick", "standard"):
        # quick + standard default: sonnet-economy. A clean A/B (Juice Shop,
        # 2026-06-23 — see docs/analysis/analysis-model-placement-...§10) showed
        # Opus reasoning costs ~+$10.77 (+36%) over sonnet-economy with NO
        # measurable quality/coverage gain; the earlier "Opus cheaper/better for
        # STRIDE" thesis was refuted (Opus-STRIDE never actually ran in the
        # measurements behind it). standard is the everyday default → favour
        # cost. Opt into Opus with --reasoning-model opus, or upgrade just the
        # severity stage with --triage-model opus.
        mode = "sonnet-economy"
    else:
        # thorough default: Opus on STRIDE/triage/merger — the premium tier
        # where full reasoning depth + architect review justify the cost.
        # Opt out with --reasoning-model sonnet-economy (or --no-opus).
        mode = "opus"

    models = dict(MODEL_MATRIX[mode])

    # Quality buy-back at the everyday `standard` default (2026-07-05): upgrade the
    # aggregation/judgment stages — triage (severity calibration) and merger (dedup)
    # — to Sonnet 5, where a Juice-Shop A/B measured a real gain (see
    # docs/model-selection.md "Benchmarks"). STRIDE stays on 4.6: Sonnet 5 REGRESSED
    # discovery recall. `quick` keeps the all-4.6 economy floor; `thorough` is Opus.
    # Env/CLI overrides below still win. Caveat: an explicit version id only takes
    # effect on the headless / hybrid-dispatch path — an interactive run inherits the
    # session model regardless (the bare `sonnet` alias resolves to the session).
    if mode == "sonnet-economy" and depth == "standard":
        models["triage"] = SONNET5
        models["merger"] = SONNET5

    # Step 2: env var override (over the matrix default).
    env_map = {
        "stride": "APPSEC_STRIDE_MODEL",
        "triage": "APPSEC_TRIAGE_MODEL",
        "merger": "APPSEC_MERGER_MODEL",
    }
    for k, env in env_map.items():
        if os.environ.get(env):
            models[k] = os.environ[env]

    # Step 3: explicit per-stage CLI flags — highest precedence (most explicit,
    # per-run intent). They win over both the matrix and the env vars. --no-opus
    # still clamps Opus→Sonnet later in resolve() via apply_opus_ban().
    cli_map = {
        "stride": getattr(ns, "stride_model", None),
        "triage": getattr(ns, "triage_model", None),
        "merger": getattr(ns, "merger_model", None),
    }
    for k, v in cli_map.items():
        if v:
            models[k] = v

    label = f"{mode} (STRIDE: {models['stride']}, triage: {models['triage']}, merger: {models['merger']})"
    return {
        "reasoning_model": mode,
        "stride_model": models["stride"],
        "triage_model": models["triage"],
        "merger_model": models["merger"],
        "reasoning_label": label,
    }


def resolve_extended_models(reasoning_mode: str, depth: str) -> dict:
    """Resolve models for agents beyond the stride/triage/merger triplet.

    Covers context-resolver, recon-scanner, qa-reviewer (split into
    routine + content), config-scanner, and the orchestrator.

    Routing rationale (verified against agent specs):

    - ``context_resolver``, ``recon_scanner``, ``config_scanner`` are
      deterministic tasks (file extraction / grep + classification /
      YAML-rule application) → **always Haiku**, regardless of depth or
      reasoning tier.
    - ``qa_content`` does invariant / contract reasoning → always Sonnet.
    - ``qa_routine`` is mechanical (link patches, anchor renames) →
      Haiku at quick + standard, Sonnet at thorough where the document
      is bigger and cross-references are denser.
    - ``orchestrator`` runs Phase 3-8 + 11 (architecture, walkthroughs,
      composer) — never on Haiku.

    Env vars (APPSEC_<AGENT>_MODEL) override per-agent for ad-hoc
    debugging or to force a specific tier on a specific phase.
    """
    reasoning_mode = canonical_reasoning_model(reasoning_mode)
    if reasoning_mode == "sonnet-economy":
        models = dict(EXTENDED_MODEL_MATRIX[("sonnet-economy", depth)])
    else:
        models = dict(_DEFAULT_EXTENDED_ROUTING)

    # Extended Sonnet-tier routing. The bare `sonnet` alias would silently follow the
    # host session (Opus / 4.6 / 5), so we replace it with concrete ids per role.
    # Skipped for the explicit `sonnet` tier (`--reasoning-model sonnet`), which keeps
    # the alias so the user gets latest Sonnet. The ORCHESTRATOR is never touched — it
    # IS the session model, which the plugin cannot set (hardcoding would make the
    # routing table lie). NOTE: these explicit-id pins bite on the headless/hybrid
    # path; an interactive run's subagents inherit the session model. Env overrides win.
    if reasoning_mode != "sonnet":
        # renderer + abuse-case verifier are the quality-showcase stages (MS / CISO
        # framing; verdict decisiveness — 4.6 punts to `inconclusive`): latest Sonnet
        # (Sonnet 5.5) at standard AND thorough, cheapest 4.6 only at the quick tier.
        showcase = SONNET5 if depth in ("standard", "thorough") else "claude-sonnet-4-6"
        for _k in ("renderer", "abuse_verifier"):
            if models.get(_k) == SONNET:
                models[_k] = showcase
        # qa_content + qa_routine are mechanical / contract stages → concrete 4.6
        # wherever they would otherwise be the bare alias (Haiku stays Haiku).
        for _k in ("qa_content", "qa_routine"):
            if models.get(_k) == SONNET:
                models[_k] = "claude-sonnet-4-6"

    env_map = {
        "context_resolver": "APPSEC_CONTEXT_RESOLVER_MODEL",
        "recon_scanner": "APPSEC_RECON_SCANNER_MODEL",
        "qa_routine": "APPSEC_QA_ROUTINE_MODEL",
        "qa_content": "APPSEC_QA_CONTENT_MODEL",
        "config_scanner": "APPSEC_CONFIG_SCANNER_MODEL",
        "orchestrator": "APPSEC_ORCHESTRATOR_MODEL",
        "renderer": "APPSEC_RENDERER_MODEL",
        "abuse_verifier": "APPSEC_ABUSE_VERIFIER_MODEL",
        "evidence_verifier": "APPSEC_EVIDENCE_VERIFIER_MODEL",
    }
    for k, env in env_map.items():
        if os.environ.get(env):
            models[k] = os.environ[env]

    return {
        "context_resolver_model": models["context_resolver"],
        "recon_scanner_model": models["recon_scanner"],
        "qa_routine_model": models["qa_routine"],
        "qa_content_model": models["qa_content"],
        "config_scanner_model": models["config_scanner"],
        "orchestrator_model": models["orchestrator"],
        "renderer_model": models["renderer"],
        "abuse_verifier_model": models["abuse_verifier"],
        "evidence_verifier_model": models["evidence_verifier"],
    }


_OPUS_TOKEN = "opus"  # matches "opus", "opus-cheap", "claude-opus-4-7"
_MODEL_FIELDS = (
    "stride_model",
    "triage_model",
    "merger_model",
    "architect_model",
    "orchestrator_model",
    "context_resolver_model",
    "recon_scanner_model",
    "qa_routine_model",
    "qa_content_model",
    "config_scanner_model",
    "renderer_model",
    "abuse_verifier_model",
)


def apply_opus_ban(cfg: dict, disable_opus: bool) -> dict:
    """Single, non-bypassable ceiling: rewrite every Opus selection to Sonnet.

    Runs LAST in resolve() — after env overrides,
    --reasoning-model resolution and the org-profile merge. That ordering
    is what makes the ceiling
    non-bypassable: an explicit ``--reasoning-model opus`` or an
    ``APPSEC_*_MODEL=claude-opus-4-7`` env override are both clamped here
    after they have been applied.

    The ban is sourced from (CLI ``--no-opus``) OR (env
    ``APPSEC_DISABLE_OPUS``) OR (org-profile ``policy.disable_opus``) — any
    one tightens, none loosens. Idempotent and a no-op when ``disable_opus``
    is False.

    Always records ``cfg["opus_disabled"]`` so the summary renderer and
    downstream consumers can see the ceiling state. Returns a patch dict to
    ``cfg.update()``.
    """
    cfg["opus_disabled"] = bool(disable_opus)
    if not disable_opus:
        return {}
    patch: dict = {}
    # 1) Tier coercion — drives labels and any downstream "is this opus?" check.
    if cfg.get("reasoning_model") in ("opus", "opus-cheap"):
        patch["reasoning_model"] = "sonnet"
    # 2) Field clamp — any *_model carrying an opus token -> sonnet. Catches
    #    both the short alias ("opus") and the full id ("claude-opus-4-7"),
    #    and covers env-var per-agent overrides on the extended agents.
    for f in _MODEL_FIELDS:
        v = cfg.get(f)
        if v and _OPUS_TOKEN in str(v).lower():
            patch[f] = "sonnet"
    # 3) Labels — make the downgrade visible, never silent.
    base_mode = patch.get("reasoning_model", cfg.get("reasoning_model"))
    patch["reasoning_label"] = f"{base_mode} (no-opus: Opus→Sonnet ceiling active)"
    if cfg.get("architect_review"):
        patch["architect_label"] = "enabled (sonnet, no-opus ceiling)"
    return patch


def resolve_stride_profile(reasoning_mode: str, depth: str, stride_cap: int | None = None) -> dict:
    """Return the STRIDE-analyzer depth profile.

    The STRIDE depth-reduction (A-F) is gated on
    ``reasoning_mode == sonnet-economy`` AND ``depth == quick``.
    Both conditions must hold to keep behaviour predictable for users
    who pick sonnet-economy at standard/thorough (no STRIDE reduction
    there) and for users who explicitly pick a non-economy tier at quick
    (e.g. ``--reasoning-model sonnet``, which preserves the pre-2026-05
    "Sonnet everywhere at quick" behaviour).

    Since 2026-05 ``sonnet-economy`` is also the default at quick depth,
    so an unflagged ``--assessment-depth quick`` invocation activates
    the A-F profile automatically — no extra flag required.

    Quick + sonnet-economy applies:
      A. Skip verification greps
      B. Cap threats per STRIDE category at 2 (was "2-5")
      C. Omit code_example field in remediation
      D. Omit evidence excerpt (file:line stays)
      E. Skip CVSS v4.0 scoring
      F. Lower TURN_BUDGET hard cap from 40 to 25

    The model itself stays Sonnet — only the task scope is reduced.

    ``stride_cap`` (the opt-in ``--stride-cap N`` flag) is an ORTHOGONAL
    cost lever: when set (>=1) it injects ``max_threats_per_category = N``
    into the emitted profile **at any depth** without enabling the other
    A-F reductions — so standard/thorough keep full CVSS/evidence/grep
    depth and only trim the Medium/Low tail per STRIDE category per
    component. The default (None) preserves the documented "standard =
    full STRIDE, reduction opt-in only" invariant. CRITICAL/HIGH-SAFE: the
    analyzer never drops a Critical or High to honour the cap (see
    ``agents/appsec-stride-analyzer-v2.md`` cap table). The cap is key-gated
    in the analyzer — it activates whenever ``max_threats_per_category``
    is present in the profile, independent of the label.
    """
    reasoning_mode = canonical_reasoning_model(reasoning_mode)
    cap = stride_cap if (stride_cap and stride_cap >= 1) else None
    if reasoning_mode == "sonnet-economy" and depth == "quick":
        profile = dict(QUICK_STRIDE_PROFILE)
        profile["stride_profile_label"] = "quick (depth-reduced via sonnet-economy)"
        if cap is not None:
            profile["max_threats_per_category"] = cap
            profile["stride_profile_label"] = f"quick (depth-reduced via sonnet-economy, per-category cap {cap})"
        return {"stride_profile": profile}
    if cap is not None:
        return {
            "stride_profile": {
                "max_threats_per_category": cap,
                "stride_profile_label": f"full (per-category cap {cap})",
            }
        }
    return {"stride_profile": {"stride_profile_label": "full"}}


def resolve_skip_attack_paths_authoring(depth: str) -> dict:
    """Skip the LLM-authored ``security-posture-attack-paths.json`` fragment
    at quick depth.

    The renderer's ``_derive_attack_paths_fallback`` (renderers/compose_threat_model.py)
    produces a deterministic CWE→class assignment when the fragment is
    missing. The fallback omits LLM-judgement fields (architectural root
    causes, attack chains) but preserves the heatmap structure and per-class
    finding lists — adequate for quick triage and saves ~1-3 min in Stage 2.

    No CLI override — users who want the authored fragment at quick can
    work around by running at standard depth instead. Standard and thorough
    keep authoring on.
    """
    if depth == "quick":
        return {
            "skip_attack_paths_authoring": True,
            "skip_attack_paths_authoring_label": "skipped (quick depth — deterministic fallback)",
        }
    return {"skip_attack_paths_authoring": False, "skip_attack_paths_authoring_label": "authored (LLM)"}


def resolve_enrich_arch_fragments(ns: argparse.Namespace, depth: str, dry_run: bool) -> dict:
    """LLM enrichment of the security-architecture.md fragment (§7).

    Note (2026-06): architecture-diagrams.md (§2) is NOT enriched — it is
    deterministic and the skill force-regenerates it from threat-model.yaml
    before AND after Stage 2, so any LLM edit was always discarded. §2 incl.
    its per-diagram ``**Key takeaway:**`` lines is owned by
    ``renderers/pregenerate_fragments.py:gen_architecture_diagrams``. This flag now
    gates security-architecture.md (§7 narrative) only.

    Default behaviour (since 2026-05):

      • quick → off (deterministic pre-generator output is canonical;
        Stage-2 enrichment was costing ~4-5 min for marginal value at
        a depth that already opts into ``diagrams=minimal``).
      • standard → enrich (the pre-generator writes a SCAFFOLD with
        NARRATIVE_PLACEHOLDER comments; without enrichment those placeholders
        ship verbatim into the output as unfilled HTML comments, making §7
        entirely empty of narrative. The ~$0.50-1.00 / ~4 min Stage-2 cost
        is the price of a usable §7 at standard depth).
      • thorough → enrich (Stage 2 LLM rewrites the two fragments).
      • dry-run → never enrich (transient output anyway).

    User overrides:

      • ``--no-enrich-arch`` forces off at any depth.
      • ``--enrich-arch`` forces on at any depth (e.g. quick + enrich).

    Token cost when enabled: ~25-30k input + ~5-8k output (~$0.50-1.00 at
    sonnet-4-6) on top of the standard Stage 2 budget.
    """
    if dry_run:
        return {"enrich_arch_fragments": False, "enrich_arch_label": "disabled (dry-run)"}
    if getattr(ns, "no_enrich_arch", False):
        return {"enrich_arch_fragments": False, "enrich_arch_label": "disabled (--no-enrich-arch)"}
    if getattr(ns, "enrich_arch", False):
        return {"enrich_arch_fragments": True, "enrich_arch_label": "enabled (--enrich-arch)"}
    if depth == "quick":
        return {"enrich_arch_fragments": False, "enrich_arch_label": "disabled (default at quick depth)"}
    if depth == "standard":
        return {"enrich_arch_fragments": True, "enrich_arch_label": "enabled (default at standard depth)"}
    return {"enrich_arch_fragments": True, "enrich_arch_label": "enabled (auto-thorough)"}


def resolve_architect_review(ns: argparse.Namespace, depth: str, dry_run: bool) -> dict:
    """Auto-enable at thorough, off at quick/standard. Dry-run force-off."""
    if dry_run:
        return {"architect_review": False, "architect_model": None, "architect_label": "disabled (dry-run)"}
    if ns.no_architect_review:
        enabled = False
        trigger = "--no-architect-review"
    elif ns.architect_review:
        enabled = True
        trigger = "--architect-review"
    elif depth == "thorough":
        enabled = True
        trigger = "auto-thorough"
    else:
        enabled = False
        trigger = "off (depth != thorough)"

    if not enabled:
        # Honour the env-var escape hatch even when off (for "always on" CI)?
        # No — the env var is about model choice, not enable/disable.
        return {"architect_review": False, "architect_model": None, "architect_label": f"disabled ({trigger})"}

    # Model resolution — default sonnet; the flag overrides with a tier alias
    # (sonnet|opus) OR an explicit version id (claude-sonnet-5, …), passed
    # through verbatim — same contract as the APPSEC_ARCHITECT_MODEL env var
    # below. --no-opus still clamps any Opus id to Sonnet in apply_opus_ban().
    #
    # The bounded semantic reviewer defaults to Sonnet. Explicit model choice
    # and the global Opus ban keep their existing precedence.
    model = ns.architect_model or "sonnet"
    if os.environ.get("APPSEC_ARCHITECT_MODEL"):
        model = os.environ["APPSEC_ARCHITECT_MODEL"]

    short = model.replace("claude-", "")
    label = f"enabled ({short}, {trigger})"
    return {"architect_review": True, "architect_model": model, "architect_label": label}


def resolve_paths(ns: argparse.Namespace, dry_run: bool, *, create_output_dir: bool = True) -> dict:
    """Resolve REPO_ROOT (via git rev-parse) and OUTPUT_DIR.

    In dry-run mode, OUTPUT_DIR is forced to a temp directory regardless
    of --output; the cleanup happens at the completion summary step.
    """
    repo_in = Path(ns.repo).resolve() if ns.repo else Path.cwd()
    if not repo_in.is_dir():
        raise SystemExit(f"Error: repository path does not exist: {repo_in}")

    if ns.repo:
        # An explicit --repo names the scan target directly. Do NOT walk up to
        # the enclosing git toplevel: when --repo points at a subdirectory nested
        # inside a larger repo (e.g. a test fixture living inside this plugin's
        # own git tree with no .git of its own), `git rev-parse --show-toplevel`
        # would silently retarget the whole parent repo. Honour what the caller
        # asked for.
        repo_root = repo_in
    else:
        # No --repo given: resolve the enclosing git root from the cwd so an
        # invocation from a subdirectory still scans the whole repository.
        # Fall back to the cwd if it is not inside a git repo.
        try:
            r = subprocess.run(
                ["git", "-C", str(repo_in), "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            repo_root = Path(r.stdout.strip()) if r.returncode == 0 and r.stdout else repo_in
        except (OSError, subprocess.SubprocessError):
            repo_root = repo_in

    if dry_run and create_output_dir:
        import tempfile

        output_dir = Path(tempfile.mkdtemp(prefix="appsec-dry-run-"))
    elif dry_run:
        import tempfile

        output_dir = Path(tempfile.gettempdir()) / "appsec-dry-run-unstarted"
    elif ns.output:
        output_dir = Path(ns.output).resolve()
    else:
        output_dir = repo_root / "docs" / "security"

    if create_output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    output_outside_repo = not _is_within(output_dir, repo_root)

    return {
        "repo_root": str(repo_root),
        "output_dir": str(output_dir),
        "output_outside_repo": output_outside_repo,
    }


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def resolve_business_context(ns: argparse.Namespace, cfg: dict) -> dict:
    """Validate ``--context`` and ``--skip-context`` for one assessment."""
    source = getattr(ns, "context", None)
    skip = bool(getattr(ns, "skip_context", False))
    out: dict[str, Any] = {
        "business_context_source": None,
        "business_context_note": None,
        "skip_business_context": skip,
    }

    if source and skip:
        raise SystemExit("Error: --context and --skip-context contradict each other. Pass one of them.")

    if source:
        if str(source).lower().startswith(("http://", "https://")):
            out["business_context_source"] = str(source)
        else:
            path = Path(str(source)).expanduser()
            if not path.is_file():
                raise SystemExit(
                    f"Error: --context {source} is neither an http(s) URL nor a readable file.\n"
                    f"  Pass a URL that serves Markdown or plain text, or a path to a local file."
                )
            out["business_context_source"] = str(path.resolve())

    return out


def read_requirements_config(plugin_root: Path) -> bool:
    """Return ``requirements_source.enabled`` from the audit-security-requirements
    skill config. Missing file / unparseable JSON → ``False``."""
    cfg = plugin_root / "skills" / "audit-security-requirements" / "config.json"
    if not cfg.is_file():
        return False
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool((data or {}).get("requirements_source", {}).get("enabled"))


# ---------------------------------------------------------------------------
# Argument parser — mirrors SKILL.md § Argument Parsing
# ---------------------------------------------------------------------------


class _SingleRepository(argparse.Action):
    """Reject a repeated --repo instead of keeping only the last selection.

    One resolution configures one checkout. The headless runner hands several
    selections to the controller's combined assessment instead.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(
                f"{option_string} may be given only once here; assess several repositories together with "
                "scripts/run-headless.sh --repo <path> --repo <path>"
            )
        setattr(namespace, self.dest, values)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="resolve_config.py",
        description="Resolve create-threat-model flags into a structured JSON.",
        add_help=False,  # the skill handles --help itself
    )
    # YAML
    p.add_argument("--yaml", action="store_true")
    p.add_argument("--no-yaml", action="store_true")
    # SARIF / pentest / requirements
    p.add_argument("--sarif", action="store_true")
    p.add_argument("--pentest-tasks", action="store_true")
    p.add_argument("--pentest-format", choices=("generic", "strix"), default="generic")
    p.add_argument("--pentest-target", default=None)
    # OWASP Threat Dragon v2 JSON. ALPHA and opt-in only — never implied by a
    # depth or preset, mirroring the export skill where `threatdragon` is
    # deliberately excluded from `--formats all`.
    p.add_argument("--threatdragon", action="store_true")
    # --requirements optionally takes a URL; use nargs='?' so both
    # "--requirements" and "--requirements https://…" work.
    p.add_argument("--requirements", nargs="?", const="", default=None)
    p.add_argument("--no-requirements", action="store_true")
    # Deprecated aliases
    p.add_argument("--with-requirements", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--ignore-requirements", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--requirements-url", default=None, help=argparse.SUPPRESS)
    # Run-mode
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--incremental", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("--rerender", action="store_true")
    p.add_argument("--keep-runtime-files", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Compact console summary — print only the essentials "
        "(repository, run, results, outputs, warnings); omit the "
        "verdict, change summary, next steps, and run statistics.",
    )
    # Tracing default flipped to ON in M3.6 (was opt-in pre-M3.6). Per-agent
    # token / turn / cost / wall-time tracking writes to .appsec-trace.log
    # — small file (~10 KB / run), zero token cost, materially better
    # diagnostics. ``--no-tracing`` opts out for environments that prefer
    # not to maintain the trace artifact (CI without log-retention budget,
    # privacy-restricted pipelines).
    p.add_argument(
        "--tracing",
        dest="tracing",
        action="store_true",
        default=None,  # None = neither flag given: an org-profile preset may decide, else ON
        help="Record per-agent token/cost/timing to .appsec-trace.log (default: ON since M3.6).",
    )
    p.add_argument(
        "--no-tracing", dest="tracing", action="store_false", help="Disable tracing — skips .appsec-trace.log creation."
    )
    # Paths
    p.add_argument("--repo", default=None, action=_SingleRepository)
    p.add_argument("--output", default=None)
    # Business context for this run: an http(s) URL or a path to a Markdown /
    # plain-text file. Interactive runs ask instead (compact full runtime); a value
    # given here is used for this run only and is not persisted to the
    # repository — that write belongs to a human, not to a pipeline.
    p.add_argument("--context", default=None)
    # Run without business context and without being asked for it.
    p.add_argument("--skip-context", dest="skip_context", action="store_true")
    # Models / depth
    p.add_argument(
        "--reasoning-model", choices=("sonnet", "opus-cheap", "opus", "sonnet-economy", "haiku-economy")
    )  # haiku-economy: deprecated alias
    # Per-stage model overrides — the inline (console) equivalent of the
    # APPSEC_{STRIDE,TRIAGE,MERGER}_MODEL env vars, but without needing
    # ~/.claude/settings.json + a session restart. Each overrides just that one
    # stage on top of the --reasoning-model tier. Highest precedence among model
    # selectors EXCEPT --no-opus, which still clamps Opus→Sonnet last. Example:
    # `--reasoning-model sonnet-economy --triage-model opus` = Sonnet STRIDE with
    # Opus triage (cheap run, calibrated severities).
    # Accept EITHER a tier alias (``sonnet`` / ``opus``) OR an explicit version id
    # (``claude-sonnet-5`` / ``claude-sonnet-4-6`` / ``claude-opus-4-7``). No
    # ``choices=`` whitelist: the version set changes too often to hardcode, and
    # the ``APPSEC_{STRIDE,TRIAGE,MERGER}_MODEL`` env vars already accept any
    # string — the CLI flags now match that. A typo'd id is passed through to the
    # Agent ``model`` param and surfaces at dispatch (same failure mode as the env
    # vars), not at parse time. The ``sonnet`` alias still follows the session; a
    # concrete id pins that exact version regardless of the host. --no-opus still
    # clamps any Opus id (alias or ``claude-opus-*``) to Sonnet last.
    _model_help = (
        "Tier alias (sonnet|opus) or explicit version id "
        "(e.g. claude-sonnet-5, claude-sonnet-4-6). Overrides the "
        "--reasoning-model tier for this stage only."
    )
    p.add_argument("--stride-model", default=None, metavar="MODEL", help=_model_help)
    p.add_argument("--triage-model", default=None, metavar="MODEL", help=_model_help)
    p.add_argument("--merger-model", default=None, metavar="MODEL", help=_model_help)
    # Opus ceiling. When set, every Opus selection anywhere in the run is
    # downgraded to Sonnet (cost/compliance ceiling). Also settable org-wide
    # via the org-profile `policy.disable_opus` key, or via the environment
    # variable APPSEC_DISABLE_OPUS=1 for CI / org-shell enforcement without
    # touching argv. The three sources OR together — any of them can tighten,
    # none can loosen. Enforced by apply_opus_ban() as the last model step in
    # resolve(), so it overrides env-var per-agent overrides and an explicit
    # --reasoning-model opus alike.
    p.add_argument(
        "--no-opus",
        action="store_true",
        dest="no_opus",
        help="Forbid Opus anywhere; downgrade every Opus model "
        "selection to Sonnet. Also settable via org-profile "
        "policy.disable_opus or env APPSEC_DISABLE_OPUS=1.",
    )
    p.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"))
    # Convenience shortcuts: --quick / --thorough for the two non-default
    # depth levels. Mapped to --assessment-depth in resolve() below.
    # Mutually exclusive with --assessment-depth and with each other —
    # detect_conflicts() raises on collision.
    p.add_argument("--quick", action="store_true", help="Shortcut for --assessment-depth quick.")
    p.add_argument("--thorough", action="store_true", help="Shortcut for --assessment-depth thorough.")
    # Opt-in per-category STRIDE threat cap (cost lever). OFF by default — the
    # full STRIDE depth at standard/thorough is preserved unless this is set.
    p.add_argument(
        "--stride-cap",
        type=int,
        default=None,
        metavar="N",
        help="Opt-in: keep at most N threats per STRIDE category per "
        "component (Critical and High findings are never dropped). "
        "Trims the Medium/Low tail to cut tokens/cost; the "
        "rest of full depth (CVSS, evidence, verification greps) "
        "stays intact. Off by default.",
    )
    p.add_argument(
        "--evidence-verifier-cap",
        type=int,
        default=None,
        metavar="N",
        help="Verify at most N non-Critical findings in Phase 10a; "
        "Critical findings do not count toward the cap. Defaults: 20 "
        "(quick), 30 (standard), 100 (thorough).",
    )
    # Screening-depth STRIDE for the internal tail (cost lever). ON by default at
    # quick/standard, OFF at thorough — see resolve_cheap_stride. Exposed / auth /
    # frontend / LLM (priority <=2) plus the file-upload / realtime / data-store /
    # core-backend anchors keep full depth, and so does every exposure-unknown
    # component (ci-cd excepted — role-identified); the rest gets a flat ~8-turn
    # six-category screening pass. Defaulting it is only safe BECAUSE of the
    # exposure-unknown fail-safe: unreliable zone tags cost budget, never depth.
    p.add_argument(
        "--cheap-stride",
        action="store_true",
        dest="cheap_stride",
        help="Force light-depth STRIDE (~8 turns, all 6 categories "
        "kept) for the internal tail at any depth; exposed, auth, "
        "frontend, LLM, file-upload, realtime, data-store and "
        "core-backend (API/gateway) components keep full depth, as "
        "does anything exposure-unknown. Default: on at "
        "quick/standard, off at thorough.",
    )
    p.add_argument(
        "--no-cheap-stride",
        action="store_true",
        dest="no_cheap_stride",
        help="Full STRIDE depth on every selected component, including the provably-internal tail and ci-cd.",
    )
    # Semantic review before triage. Auto-on at thorough.
    p.add_argument(
        "--architect-review",
        action="store_true",
        help="Review and correct finding ratings and remediation before triage at any depth.",
    )
    p.add_argument("--no-architect-review", action="store_true", help="Skip semantic architect review.")
    p.add_argument(
        "--architect-model",
        default=None,
        metavar="MODEL",
        help="Tier alias (sonnet|opus) or explicit version id for the "
        "architect review. Default sonnet; --no-opus clamps any Opus id to Sonnet.",
    )
    # Architecture-fragment enrichment (M3.3 / D2). On by default at standard
    # and thorough; off at quick since 2026-05.
    p.add_argument(
        "--no-enrich-arch",
        action="store_true",
        dest="no_enrich_arch",
        help="Disable LLM enrichment of the security-architecture.md "
        "(§7) fragment (on by default at standard/thorough). "
        "architecture-diagrams.md/§2 is always deterministic.",
    )
    p.add_argument(
        "--enrich-arch",
        action="store_true",
        dest="enrich_arch",
        help="Force LLM enrichment of the security-architecture.md "
        "(§7) fragment at any depth (overrides the quick-depth "
        "default-off).",
    )
    # v2 13-section §7 layout — the only supported layout.
    # `--schema-v2` is kept as a no-op alias so explicit declarations in
    # CI scripts do not break. `--schema-v1` is accepted by the parser only
    # to return a clear removal error instead of "unrecognized argument".
    p.add_argument(
        "--schema-v2",
        action="store_true",
        dest="schema_v2",
        help="Explicitly request the 13-section §7 security "
        "architecture layout. No-op because v2 is the only "
        "supported schema.",
    )
    p.add_argument(
        "--schema-v1",
        action="store_true",
        dest="schema_v1",
        help="Removed legacy option. Schema v2 is the only supported §7 layout.",
    )
    # Walkthroughs opt-out (2026-05). Stage 2 normally authors
    # `attack-walkthroughs.md` (sequence diagrams per Critical) — costs
    # ~1 min in quick depth, more in thorough. Skipping renders §3 with
    # the deterministic chain-overview only, no per-finding sequence
    # diagrams. Useful for CI / regression / fast iteration.
    p.add_argument(
        "--no-walkthroughs",
        action="store_true",
        dest="no_walkthroughs",
        help="Skip authoring attack-walkthroughs.md in Stage 2; §3 falls back to chain-overview-only rendering.",
    )
    # Abuse-case verification gating (2026-06). Stage 1d runs a deterministic
    # matcher + per-candidate verifier fan-out that confirms attack chains and
    # can elevate keystone findings. ON by default at standard/thorough; the
    # quick fast-mode skips it. --abuse-cases forces it on at any depth;
    # --no-abuse-cases forces it off at any depth. Mutually exclusive
    # (detect_conflicts()).
    p.add_argument(
        "--abuse-cases",
        action="store_true",
        dest="abuse_cases",
        help="Force abuse-case verification ON at any depth (overrides the quick-depth default-off).",
    )
    p.add_argument(
        "--no-abuse-cases",
        action="store_true",
        dest="no_abuse_cases",
        help="Force abuse-case verification OFF at any depth "
        "(skip the Stage 1d verifier fan-out even at "
        "standard/thorough).",
    )
    p.add_argument(
        "--abuse-case-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Add a repository-local YAML abuse-case file for this scan. May be repeated.",
    )
    p.add_argument(
        "--only-abuse-case",
        action="append",
        default=[],
        metavar="ID",
        help="Verify only the named active abuse case. May be repeated.",
    )
    p.add_argument(
        "--register-severity-floor",
        dest="register_severity_floor",
        choices=("critical", "high", "medium", "low", "informational"),
        default=None,
        help="Drop threats below this severity from the canonical "
        "register and every downstream count. Default 'medium' "
        "(Low/Informational excluded — they are noise in a "
        "threat model). Pass 'low' to keep Low findings.",
    )
    # PR / base / no-qa
    p.add_argument("--base", default=None)
    p.add_argument("--pr-mode", action="store_true")
    p.add_argument("--no-qa", action="store_true")
    # Scan manifest — log all scanned files to OUTPUT_DIR/.scan-manifest.txt
    p.add_argument("--scan-manifest", action="store_true")
    # Optional model slug — when set, the run additionally emits a
    # postfix-stamped, copy-ready deliverable set (threat-model-<slug>.md /
    # .yaml / .figure*.svg / …) so several models can share one directory
    # without overwriting each other. Default None = canonical names only.
    p.add_argument(
        "--slug",
        nargs="?",
        const="__auto__",
        default=None,
        help="Postfix for an additional copy-ready deliverable set "
        "(threat-model-<slug>.*). Bare --slug generates a "
        "random one; --slug <value> uses it. Default: none.",
    )
    # Suppress interactive confirmation prompts (auto-accept current mode).
    p.add_argument(
        "--no-confirm",
        "--yes",
        action="store_true",
        dest="no_confirm",
        help="Skip interactive confirmation prompts; accept auto-detected mode.",
    )
    # M11 — wall-time hard deadline. Skill watchdog checks the elapsed seconds
    # since ASSESSMENT_START_EPOCH and aborts the in-flight Stage 1/2/3/4
    # Agent dispatch via TaskStop when reached. Format accepts plain seconds
    # ("3600"), minutes ("60m"), or hours ("1h"). Default unset = no deadline.
    p.add_argument(
        "--max-wall-time",
        type=str,
        default=None,
        metavar="DURATION",
        help="Hard wall-time deadline (e.g. 3600, 60m, 1h). "
        "Skill watchdog aborts the run when reached. "
        "Default: unbounded.",
    )
    # Soft cost budget (USD). It steers the run and never kills it: admission
    # refuses an invocation that cannot fit, and the run finishes even when it
    # overruns. `--max-cost` is the deprecated spelling; the name promised a
    # maximum this value is not.
    p.add_argument(
        "--soft-budget",
        "--max-cost",
        type=float,
        default=None,
        dest="soft_budget",
        metavar="USD",
        help="Soft cost budget in USD (e.g. 30.0). A run that cannot fit it "
        "does not start; a run that overruns it still finishes and reports "
        "the overrun. Not a hard cap — use the wrapper's --hard-budget for "
        "that. Default: unbounded.",
    )
    # Negative flags for tri-state semantics. When org profiles set output
    # defaults via a preset, the user needs an explicit way to opt back
    # out without selecting a different preset. ``--sarif`` still wins over
    # ``--no-sarif`` (positive overrides negative) for compatibility with
    # the existing direct-flag-wins precedence.
    p.add_argument(
        "--no-sarif", action="store_true", dest="no_sarif", help="Disable SARIF export even if a preset enables it."
    )
    p.add_argument(
        "--no-pentest-tasks",
        action="store_true",
        dest="no_pentest_tasks",
        help="Disable pentest-tasks export even if a preset enables it.",
    )
    p.add_argument(
        "--no-pdf", action="store_true", dest="no_pdf", help="Disable PDF export even if a preset enables it."
    )

    # Org-profile selection flags. These are consumed by resolve_org_profile.
    # The resolver merges the resulting defaults below CLI flags.
    # Cover-page branding. Local overrides for the org-profile `branding`
    # block; consumed by renderers/compose_threat_model.py via .skill-config.json.
    p.add_argument(
        "--report-title", default=None, help="Override the report cover title (project name is still appended)."
    )
    p.add_argument("--contact-name", default=None, help="Contact name shown in the report cover metadata.")
    p.add_argument("--contact-email", default=None, help="Contact e-mail shown in the report cover metadata.")
    p.add_argument("--logo", default=None, help="Cover logo: local file path or http(s) URL (staged before render).")

    p.add_argument("--org-profile", default=None, help="Path to an org-profile YAML; overrides the packaged default.")
    p.add_argument("--preset", default=None, help="Name of the preset to use from the active org profile.")
    p.add_argument(
        "--no-org-profile", action="store_true", help="Ignore any packaged or env-pointed org profile for this run."
    )

    # Skill-layer flags. The resolver itself does not act on them but
    # accepts them so ``--validate-only`` does not reject documented
    # create-threat-model invocations. The skill layer reads these
    # directly from argv.
    p.add_argument("--pdf", action="store_true", help="Skill-layer flag — exports threat-model.pdf after Stage 4.")
    p.add_argument("--html", action="store_true", help="Skill-layer flag — exports threat-model.html after Stage 4.")
    p.add_argument(
        "--embed-figures",
        action="store_true",
        help="Embed Figure 1 inline in threat-model.md as a base64 data: URI "
        "(self-contained doc); figure1.svg is still written. NOTE: GitHub "
        "strips data: URIs, so the default file reference is best for GitHub.",
    )
    p.add_argument(
        "--max-resumes", type=int, default=None, help="Skill-layer flag — cap on Stage 1 auto-resume dispatches."
    )
    p.add_argument("--clean-cache", action="store_true", help="Skill-layer flag — clean cache and exit.")
    p.add_argument(
        "--clean-all", action="store_true", help="Skill-layer flag — clean everything in OUTPUT_DIR and exit."
    )

    # Remaining positional args = scope words.
    p.add_argument("scope", nargs="*")
    return p


# ---------------------------------------------------------------------------
# Full resolution — orchestrates the pieces
# ---------------------------------------------------------------------------


def resolve(
    argv: list[str],
    plugin_root: Path,
    *,
    create_output_dir: bool = True,
    source_count: int | None = None,
) -> dict:
    if source_count is not None and (type(source_count) is not int or not 0 <= source_count <= 320_000):
        raise SystemExit("Error: invalid captured source count")
    parser = build_parser()
    ns = parser.parse_args(argv)

    # Deprecated-alias mapping (silent — no emitted deprecation warning here;
    # the skill layer prints the note).
    if ns.with_requirements and ns.requirements is None:
        ns.requirements = ""
    if ns.ignore_requirements:
        ns.no_requirements = True
    if ns.requirements_url and ns.requirements is None:
        ns.requirements = ns.requirements_url

    # Conflict detection must run BEFORE the shortcut → depth mapping so that
    # --quick + --thorough surfaces the right boolean-pair error rather than
    # the assessment-depth-disagreement error below.
    err = detect_conflicts(ns)
    if err:
        raise SystemExit(f"Error: {err}")
    if getattr(ns, "schema_v1", False):
        raise SystemExit(
            "Error: --schema-v1 was removed. Schema v2 is the only supported §7 security-architecture layout."
        )

    # Depth shortcuts: --quick / --thorough are sugar for --assessment-depth.
    # Reject collision with an explicit --assessment-depth that disagrees;
    # silently accept agreement (--quick --assessment-depth quick is fine).
    for short_attr, depth_value in (("quick", "quick"), ("thorough", "thorough")):
        if getattr(ns, short_attr, False):
            if ns.assessment_depth and ns.assessment_depth != depth_value:
                raise SystemExit(
                    f"Error: --{short_attr} conflicts with --assessment-depth {ns.assessment_depth}. Pick one."
                )
            ns.assessment_depth = depth_value

    # Build the resolved config by composing per-resolver outputs.
    cfg: dict[str, Any] = {
        "invocation_args": " ".join(argv),
        "scope": ns.scope,
        "dry_run": ns.dry_run,
        "write_sarif": ns.sarif,
        "write_pentest_tasks": ns.pentest_tasks,
        "pentest_format": ns.pentest_format,
        "pentest_target": ns.pentest_target,
        "write_threatdragon": bool(ns.threatdragon),
        "keep_runtime_files": ns.keep_runtime_files,
        "slug": (secrets.token_hex(2) if ns.slug == "__auto__" else ns.slug),
        "verbose": ns.verbose,
        "quiet": ns.quiet,
        "tracing": True if ns.tracing is None else ns.tracing,
        "resume": ns.resume,
        "pr_mode": ns.pr_mode,
        "base_ref": ns.base,
        "scan_manifest": ns.scan_manifest,
        "no_confirm": ns.no_confirm,
        # Persisted to .skill-config.json so renderers/compose_threat_model.py honours it
        # on EVERY invocation (renderer, recompose, fragment-fixer) without
        # threading a CLI flag through each call site.
        "embed_figures": bool(ns.embed_figures),
        # Cover branding. CLI value (or None) here; an active org profile may
        # fill in a None field in _apply_org_profile (CLI always wins).
        "report_title": ns.report_title,
        "contact_name": ns.contact_name,
        "contact_email": ns.contact_email,
        "logo": ns.logo,
        "write_pdf": bool(ns.pdf),
        "write_html": bool(ns.html),
    }

    cfg.update(resolve_write_yaml(ns))
    cfg.update(resolve_requirements(ns, read_requirements_config(plugin_root)))

    depth_info = resolve_assessment_depth(ns)
    cfg.update(depth_info)
    cfg.update(resolve_stride_concurrency())
    if ns.evidence_verifier_cap is not None and ns.evidence_verifier_cap < 1:
        raise SystemExit("Error: --evidence-verifier-cap must be at least 1")
    cfg.update(resolve_evidence_verifier_cap(ns, depth_info["assessment_depth"]))

    quick_depth = depth_info["assessment_depth"] == "quick"
    env_skip_qa = os.environ.get("APPSEC_SKIP_QA") == "1"
    cfg["skip_qa"] = bool(ns.no_qa or env_skip_qa or quick_depth)
    if ns.no_qa:
        cfg["skip_qa_label"] = "skipped (--no-qa)"
    elif env_skip_qa:
        cfg["skip_qa_label"] = "skipped (APPSEC_SKIP_QA=1)"
    elif quick_depth:
        cfg["skip_qa_label"] = "skipped (auto - quick depth)"
    else:
        cfg["skip_qa_label"] = "enabled"

    # Cheap-stride screening tier. Read by build_stride_dispatch_manifest from
    # .skill-config.json; the manifest decides which components qualify.
    cfg.update(resolve_cheap_stride(ns, cfg["assessment_depth"]))

    # Quick-depth post-override for requirements — force off unless the
    # user explicitly opted in via --requirements.
    if cfg["assessment_depth"] == "quick" and ns.requirements is None and not ns.no_requirements:
        cfg["check_requirements"] = False
        cfg["requirements_label"] = "disabled (auto — quick depth)"

    cfg.update(resolve_reasoning_model(ns, depth_info["assessment_depth"]))
    cfg.update(resolve_extended_models(cfg["reasoning_model"], depth_info["assessment_depth"]))
    cfg.update(
        resolve_stride_profile(
            cfg["reasoning_model"],
            depth_info["assessment_depth"],
            getattr(ns, "stride_cap", None),
        )
    )
    cfg.update(resolve_architect_review(ns, depth_info["assessment_depth"], ns.dry_run))
    cfg.update(resolve_enrich_arch_fragments(ns, depth_info["assessment_depth"], ns.dry_run))
    cfg["security_schema"] = "v2"
    cfg["security_schema_label"] = "v2 (13-section security architecture layout)"
    cfg.update(resolve_skip_attack_paths_authoring(depth_info["assessment_depth"]))
    # Walkthroughs opt-out (2026-05). Quick depth is the fast mode and skips
    # per-finding sequenceDiagram authoring by default; standard/thorough only
    # skip it when the user passes --no-walkthroughs.
    cfg["skip_attack_walkthroughs"] = bool(getattr(ns, "no_walkthroughs", False) or quick_depth)
    if getattr(ns, "no_walkthroughs", False):
        cfg["skip_attack_walkthroughs_label"] = "skipped (--no-walkthroughs)"
    elif quick_depth:
        cfg["skip_attack_walkthroughs_label"] = "skipped (auto - quick depth)"
    else:
        cfg["skip_attack_walkthroughs_label"] = "authored (LLM)"
    cfg.update(resolve_abuse_case_verification(ns, depth_info["assessment_depth"]))
    cfg.update(resolve_paths(ns, ns.dry_run, create_output_dir=create_output_dir))
    # Paths are consumed as data by model/resolve_abuse_cases.py, which constrains
    # them to REPO_ROOT before reading. Never interpolate these values in Bash.
    cfg["abuse_case_files"] = list(ns.abuse_case_file or [])
    cfg["only_abuse_case_ids"] = list(ns.only_abuse_case or [])

    # B2c — repo-size auto-cap. Must run after resolve_paths so we have
    # the final repo_root value, and after resolve_assessment_depth so we
    # know the tier.
    cfg.update(resolve_repo_size_cap(cfg, Path(cfg["repo_root"]), source_count=source_count))

    # Orchestrator (session-model) recommendation — advisory, runs at ALL depths.
    # Surfaced in the pre-flight box and, interactively, an optional prompt
    # (compact full runtime). The user always makes the final choice; a divergent choice
    # requires a session restart (a running loop cannot switch its own model).
    cfg.update(
        recommend_orchestrator_model(
            _count_source_files(Path(cfg["repo_root"])) if source_count is None else source_count
        )
    )

    # (Removed 2026-06: the B2d large-repo reasoning-tier auto-downgrade.
    # Large repos are exactly where Opus reasoning pays off — better
    # calibration and, via lower cache-read churn, at worst cost-neutral —
    # so forcing them down to Sonnet was backwards. repo_size_capped is now
    # purely informational. See docs/analysis/plan-opus-stride-default-2026-06-21.md.)

    # Controller admission refuses every other lifecycle mode before resolution.
    cfg["mode"] = "full"

    cfg.update(resolve_business_context(ns, cfg))

    # M11 — wall-time deadline parsing. Accept "3600" (s), "60m", "1h".
    cfg["max_wall_time_seconds"] = _parse_duration(ns.max_wall_time) if ns.max_wall_time else None
    # Soft cost budget. Plain float USD.
    cfg["soft_budget_usd"] = ns.soft_budget

    # Plugin metadata (always present).
    cfg["plugin_root"] = str(plugin_root)
    cfg["plugin_version"] = _read_plugin_version(plugin_root)
    cfg["analysis_version"] = _read_analysis_version(plugin_root)

    # Org-profile resolution. Runs last so it can inspect the already-resolved
    # cfg (e.g. assessment_depth for quick_default_active rules). Direct CLI
    # flags always win — org-profile only fills in fields that were not
    # explicitly toggled by the user.
    cfg.update(_apply_org_profile(ns, cfg, plugin_root))

    # There is one producer generation. The controller separately rejects
    # modes for which that runtime has no safe compact implementation.
    cfg.update(resolve_runtime_generation())

    # Opus ceiling — MUST be the last model step. Sourced from (CLI --no-opus)
    # OR (env APPSEC_DISABLE_OPUS) OR (org-profile policy.disable_opus, merged
    # into cfg["disable_opus"] by _apply_org_profile above). Running here —
    # after every resolver, env override, and the org merge — is what makes the
    # ceiling non-bypassable.
    disable_opus = bool(
        getattr(ns, "no_opus", False)
        or os.environ.get("APPSEC_DISABLE_OPUS", "").strip().lower() in ("1", "true", "yes", "on")
        or cfg.get("disable_opus")
    )
    cfg.update(apply_opus_ban(cfg, disable_opus))

    # RC.A — emit `total_stages` deterministically so the skill banner does
    # not have to compute it from runtime prose. Formula:
    #   2 (Stage 1 + Stage 2)
    #   + 1 when QA runs (not SKIP_QA and not DRY_RUN)
    #   + 1 when Architect Review runs (architect_review and not DRY_RUN)
    cfg["total_stages"] = _compute_total_stages(cfg)

    # Normalise a relative local logo path (from --logo) against the current
    # working directory so renderers/compose_threat_model.py — which runs from a
    # different CWD — can resolve it. URLs and absolute paths (incl. an
    # org-profile logo already absolutised against its profile dir) are
    # unchanged.
    _logo = cfg.get("logo")
    if _logo and not str(_logo).lower().startswith(("http://", "https://")):
        _lp = Path(str(_logo)).expanduser()
        if not _lp.is_absolute():
            cfg["logo"] = str((Path.cwd() / _lp).resolve())

    return cfg


def resolve_assessment(scope, argv: list[str], plugin_root: Path, *, model: str | None = None) -> dict:
    """Resolve shared full-run settings without selecting a primary repository.

    Admission belongs to the controller. Configuration uses each root's frozen
    snapshot and a captured source count, so ordinary resolver Git helpers and
    repository hooks cannot run on selected checkouts. Source grants are never
    reconstructed from the returned configuration.
    """
    from analyzers.repo_profile import classify

    from runtime.multi_repo_scope import AssessmentScope

    if not isinstance(scope, AssessmentScope):
        raise SystemExit("Error: combined configuration requires an admitted assessment scope")
    parser = build_parser()
    ns = parser.parse_args(argv)
    if ns.repo or ns.output or ns.resume or ns.dry_run or ns.rerender or ns.rebuild or ns.incremental:
        raise SystemExit("Error: combined scope and lifecycle flags belong to controller admission")
    # Shared configuration is deliberately compared across every frozen root;
    # choosing equivalent settings is not a first-root policy override.
    source_count = sum(classify(path)[1] == "code" for repo in scope.repositories for path in repo.files)
    transient = {"repo_root", "invocation_args"}
    candidates = []
    for repo in scope.repositories:
        with scope.scanner_snapshot(repo.repository_id) as root:
            cfg = resolve(
                ["--repo", str(root), "--output", str(scope.output), "--full", *argv],
                plugin_root,
                create_output_dir=False,
                source_count=source_count,
            )
        candidates.append({key: value for key, value in cfg.items() if key not in transient})
    if any(cfg != candidates[0] for cfg in candidates[1:]):
        raise SystemExit("Error: selected repositories have incompatible assessment-wide configuration")
    cfg = candidates[0]
    if model:
        explicit = {"stride_model": ns.stride_model, "triage_model": ns.triage_model, "merger_model": ns.merger_model}
        for key in tuple(cfg):
            if key.endswith("_model") and key != "reasoning_model" and not explicit.get(key):
                cfg[key] = model
        cfg.update(apply_opus_ban(cfg, bool(cfg.get("opus_disabled") or cfg.get("disable_opus"))))
    # MD-9: each combined STRIDE artifact comes back from one tool-less call, where
    # Sonnet 4.6 exhausts its thinking without returning one at any effort level
    # (user-service replay, 2026-10-11). Only the economy pin moves; an explicit
    # stage model, environment pin, or shared model is kept and warned about.
    if (
        cfg.get("stride_model") == SONNET46
        and not (ns.stride_model or os.environ.get("APPSEC_STRIDE_MODEL") or model)
    ):
        cfg["stride_model"] = SONNET5
        cfg["stride_model_moved_from"] = SONNET46
        cfg["reasoning_label"] = (
            f"{cfg['reasoning_model']} (STRIDE: {SONNET5}, triage: {cfg['triage_model']}, "
            f"merger: {cfg['merger_model']})"
        )
    # MD-10: controller discovery returns validated components and cited
    # interfaces from tool-less calls. On Juice Shop (2026-10-14) Haiku passed
    # the thinking stop or repeated a rejected artifact until the exchange
    # limit; Sonnet 5.5 returned a valid one in two calls. Only the Haiku
    # default of the recon role moves.
    if (
        cfg.get("recon_scanner_model") == HAIKU
        and not (os.environ.get("APPSEC_RECON_SCANNER_MODEL") or model)
    ):
        cfg["recon_scanner_model"] = SONNET5
    cfg.update(
        assessment_scope="multiple-repositories",
        source_scope_sha256=scope.inventory()["scope_sha256"],
        repository_ids=sorted(repo.repository_id for repo in scope.repositories),
        invocation_args=" ".join(argv),
    )
    return cfg


def _compute_total_stages(cfg: dict) -> int:
    """RC.A — programmatic total_stages for the Stage handoff banner.

    Stays in lock-step with the compact runtime's Stage-1 handoff banner:
    'start with 2 for Stage 1 (orchestrator) + Stage 2 (composition),
    add 1 when SKIP_QA=false and DRY_RUN=false, and add 1 when
    ARCHITECT_REVIEW=true and DRY_RUN=false'.
    """
    dry = bool(cfg.get("dry_run"))
    skip_qa = bool(cfg.get("skip_qa"))
    arch = bool(cfg.get("architect_review"))
    total = 2
    if not dry and not skip_qa:
        total += 1
    if not dry and arch:
        total += 1
    return total


def _apply_org_profile(ns: argparse.Namespace, cfg: dict, plugin_root: Path) -> dict:
    """Layer org-profile defaults under the user's CLI flags.

    Returns a dict of fields to ``cfg.update()``. When no org profile is
    active the returned dict carries only inert metadata so downstream
    behaviour is bit-identical to a pre-org-profile run.
    """
    try:
        rop = _load_resolve_org_profile_module(plugin_root)
    except Exception as exc:  # noqa: BLE001
        # Resolver missing or import error: leave behaviour unchanged.
        return {
            "org_profile": {"active": False, "source": "unavailable", "error": str(exc)},
            "preset": None,
            "org_profile_defaults": {},
            "org_profile_requirements_source": None,
            "org_profile_skill_toggles": {},
            "org_profile_context_documents": [],
            "org_profile_security_coach": None,
            "org_profile_llm_policy": None,
        }
    effective, errors = rop.resolve(
        ns.org_profile,
        ns.preset,
        bool(getattr(ns, "no_org_profile", False)),
        ns.repo,
        plugin_root,
    )
    if errors:
        # Hard-fail early; the skill layer expects the resolver to refuse
        # an invocation against an invalid profile so Stage 1 never starts.
        raise SystemExit("Error: " + "; ".join(errors))

    org_block = {
        "org_profile": effective["org_profile"],
        "preset": effective.get("preset"),
        "org_profile_defaults": effective.get("defaults") or {},
        "org_profile_requirements_source": effective.get("requirements_source"),
        "org_profile_skill_toggles": effective.get("skill_toggles") or {},
        "org_profile_context_documents": effective.get("llm_context_documents") or [],
        "org_profile_security_coach": effective.get("security_coach"),
        "org_profile_llm_policy": effective.get("llm_policy"),
    }
    if not effective["org_profile"].get("active"):
        return org_block

    defaults = effective.get("defaults") or {}

    # Tri-state booleans: positive CLI > negative CLI > preset > current.
    def _resolve_bool(cli_pos: bool, cli_neg: bool, preset_val, current: bool) -> bool:
        if cli_pos:
            return True
        if cli_neg:
            return False
        if isinstance(preset_val, bool):
            return preset_val
        return current

    org_block["write_sarif"] = _resolve_bool(ns.sarif, ns.no_sarif, defaults.get("write_sarif"), cfg["write_sarif"])
    org_block["write_pentest_tasks"] = _resolve_bool(
        ns.pentest_tasks,
        ns.no_pentest_tasks,
        defaults.get("write_pentest_tasks"),
        cfg["write_pentest_tasks"],
    )

    # Org-wide Opus ceiling (policy.disable_opus). Carried into cfg so the
    # apply_opus_ban() step at the end of resolve() OR-combines it with the
    # --no-opus flag and the APPSEC_DISABLE_OPUS env var.
    org_block["disable_opus"] = bool(defaults.get("disable_opus"))

    # Requirements defaults: direct CLI flags still win, but an active org
    # profile with a requirements source must override the legacy config default.
    # The fetch gate reads the actual URL from .org-profile-effective.json; this
    # merge only decides whether CHECK_REQUIREMENTS is on for the create skill.
    profile_rs = effective.get("requirements_source") or {}
    if profile_rs.get("requirements_yaml_url") and ns.requirements is None and not ns.no_requirements:
        ctm = profile_rs.get("create_threat_model") or {}
        enabled = bool(ctm.get("default_active", True))
        reason = "org-profile"
        if isinstance(defaults.get("check_requirements"), bool):
            enabled = bool(defaults["check_requirements"])
            reason = "org-profile preset"
        if cfg.get("assessment_depth") == "quick" and "quick_default_active" in ctm:
            quick_enabled = bool(ctm.get("quick_default_active"))
            if not quick_enabled:
                enabled = False
                reason = "org-profile quick default"
            elif not isinstance(defaults.get("check_requirements"), bool):
                enabled = True
                reason = "org-profile quick default"

        org_block["check_requirements"] = enabled
        org_block["requirements_url_override"] = None
        req_name = profile_rs.get("label") or profile_rs.get("requirements_yaml_url")
        if enabled:
            org_block["requirements_label"] = f"enabled ({reason}: {req_name})"
        else:
            org_block["requirements_label"] = f"disabled ({reason})"

    # Cover branding: a local CLI flag always wins; otherwise the org-profile
    # `branding` value fills the field. cfg already carries the CLI value (or
    # None) from the base dict, so only override when CLI was absent.
    for _bkey, _cli_val in (
        ("report_title", ns.report_title),
        ("contact_name", ns.contact_name),
        ("contact_email", ns.contact_email),
        ("logo", ns.logo),
    ):
        if _cli_val is None and defaults.get(_bkey) is not None:
            org_block[_bkey] = defaults[_bkey]

    # Tracing / scan_manifest: preset wins when user did not pass the flag.
    # --tracing/--no-tracing leave None when neither is given; --scan-manifest
    # has no negative flag, so falsy already means "not passed" there.
    if ns.tracing is None and isinstance(defaults.get("tracing"), bool):
        org_block["tracing"] = defaults["tracing"]
    if not ns.scan_manifest and isinstance(defaults.get("scan_manifest"), bool):
        org_block["scan_manifest"] = defaults["scan_manifest"]

    # Guardrails — only apply when the user did not set the corresponding flag.
    if ns.max_wall_time is None and defaults.get("max_wall_time"):
        try:
            org_block["max_wall_time_seconds"] = _parse_duration(defaults["max_wall_time"])
        except (TypeError, ValueError):
            pass
    # `max_cost_usd` is the deprecated spelling of `soft_budget_usd`; the new
    # key wins when a profile carries both.
    if ns.soft_budget is None:
        for _key in ("soft_budget_usd", "max_cost_usd"):
            if isinstance(defaults.get(_key), (int, float)):
                org_block["soft_budget_usd"] = float(defaults[_key])
                break

    return org_block


def _load_resolve_org_profile_module(plugin_root: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "resolve_org_profile",
        plugin_root / "scripts" / "runtime/resolve_org_profile.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _parse_duration(value: str) -> int:
    """Parse "3600", "60m", "1h" → seconds. Raises ValueError on malformed."""
    s = (value or "").strip().lower()
    if not s:
        raise ValueError("empty duration")
    if s.endswith("h"):
        return int(float(s[:-1]) * 3600)
    if s.endswith("m"):
        return int(float(s[:-1]) * 60)
    if s.endswith("s"):
        return int(float(s[:-1]))
    return int(float(s))


def _read_plugin_version(plugin_root: Path) -> str:
    try:
        r = subprocess.run(
            ["python3", str(plugin_root / "scripts" / "runtime/plugin_meta.py"), "get", "plugin_version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return r.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _read_analysis_version(plugin_root: Path) -> int:
    try:
        r = subprocess.run(
            ["python3", str(plugin_root / "scripts" / "runtime/plugin_meta.py"), "get", "analysis_version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return int(r.stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0
