#!/usr/bin/env python3
"""Resolve create-threat-model skill flags → fully-resolved config JSON.

Replaces ~380 lines of flag-resolution prose in ``skills/create-threat-model/
SKILL.md``. The skill now calls this script once with the raw user argv
and uses the emitted JSON to drive Stage 1 / Stage 2 / Stage 3 / Stage 4. Every
resolver (Requirements, YAML, Depth, Reasoning, Architect, Path,
Incremental, Compat) is a pure function with unit tests — the skill layer
carries no resolution logic of its own beyond reading the JSON.

Usage:
    resolve_config.py [flags...] [scope-words...]

Emission:
    - JSON on stdout with the fully-resolved configuration.
    - If ``OUTPUT_DIR`` was resolvable and ``--emit-file`` is set (default
      when OUTPUT_DIR is writable), the same JSON is also written to
      ``$OUTPUT_DIR/.skill-config.json`` for downstream scripts to consume.

Exit codes:
    0 — resolution succeeded.
    2 — conflicting flags (e.g. --full + --incremental) or a hard-fail
        precondition (e.g. --incremental with no baseline on disk).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import wrap
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
        # triage stays on Sonnet: scripts/triage_validate_ratings.py provides a
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
SONNET5 = "claude-sonnet-5"

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
        "recon_scanner":    HAIKU,
        "qa_routine":       HAIKU,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
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
        "renderer":         SONNET,
        "abuse_verifier":   SONNET,
        "evidence_verifier": SONNET,
    },
    ("sonnet-economy", "standard"): {
        "context_resolver": HAIKU,
        "recon_scanner":    HAIKU,
        "qa_routine":       HAIKU,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
        "renderer":         SONNET,
        "abuse_verifier":   SONNET,
        "evidence_verifier": SONNET,
    },
    ("sonnet-economy", "thorough"): {
        "context_resolver": HAIKU,
        "recon_scanner":    HAIKU,
        "qa_routine":       SONNET,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
        "renderer":         SONNET,
        "abuse_verifier":   SONNET,
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
    "recon_scanner":    HAIKU,
    "qa_routine":       SONNET,
    "qa_content":       SONNET,
    "config_scanner":   HAIKU,
    "orchestrator":     SONNET,
    "renderer":         SONNET,
    "abuse_verifier":   SONNET,
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
    "skip_verification_greps": True,   # A
    "max_threats_per_category": 1,     # B (was 2 — quick is a triage pass.
                                       #     Keep only the top-severity threat
                                       #     per STRIDE category per component.
                                       #     CRITICAL-SAFE: the analyzer never
                                       #     drops a Critical to honour this cap
                                       #     — see appsec-stride-analyzer.md
                                       #     Quick-mode table exception.)
    "skip_code_examples":      False,  # C (R9 — was True; flipped 2026-05.
                                       #     User feedback: mitigations without
                                       #     code hints are not actionable.
                                       #     Marginal cost ≈ 200-400 output
                                       #     tokens per mitigation × ~20
                                       #     mitigations ≈ <1 min added to a
                                       #     ~33-min Quick run. Real turn-
                                       #     budget savings come from A/B/E/F.)
    "skip_evidence_excerpt":   False,  # D (P3 — was True; cheap to keep, restores §8 evidence)
    "skip_cvss_scoring":       True,   # E
    "turn_budget_hard_cap":    25,     # F (was 40)
}

# NOTE: the per-depth STRIDE-component COUNT (formerly "components": 3/5/8) was
# removed 2026-06-07. The analyzed-component set is no longer a hard-coded number
# — it is derived from criteria (exposure / ci-cd / crown-jewel) by
# build_stride_dispatch_manifest.py:select_stride_components(). Depth changes only
# the STRIDE turn budget + diagram/QA depth here; WHICH components get analyzed is
# decided by the criteria predicate over the full inventory in .components.json.
DEPTH_PARAMS = {
    "quick":    {"simple": 10, "moderate": 15, "complex": 20,
                 "diagrams": "minimal",  "qa": "core", "qa_label": "skipped",
                 "max_repair_iterations": 1},
    "standard": {"simple": 15, "moderate": 22, "complex": 31,
                 "diagrams": "standard", "qa": "full", "qa_label": "full",
                 "max_repair_iterations": 1},
    "thorough": {"simple": 20, "moderate": 28, "complex": 35,
                 "diagrams": "extended", "qa": "extended", "qa_label": "extended",
                 "max_repair_iterations": 3},
}
# ``max_repair_iterations`` — the hard cap on the Stage-3 QA / Stage-4 architect
# Re-Render Loop. At quick/standard the loop is a SINGLE quick-fix pass (one
# repair attempt, then fail-closed `exit 2` if the contract still does not hold —
# never ship an invalid report). thorough keeps the historical budget of 3.
# Consumed by skills/create-threat-model/SKILL-impl.md (the loop reads
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
# host with APPSEC_STRIDE_CONCURRENCY (1..32).
STRIDE_DISPATCH_CONCURRENCY = 8
STRIDE_DISPATCH_CONCURRENCY_MAX = 32


# ---------------------------------------------------------------------------
# Conflict detection — runs before any resolution
# ---------------------------------------------------------------------------


CONFLICT_PAIRS: list[tuple[str, str, str]] = [
    # (attr_a, attr_b, error_message)
    ("yaml",         "no_yaml",         "--yaml and --no-yaml cannot be used together."),
    ("requirements", "no_requirements", "--requirements and --no-requirements cannot be used together."),
    ("full",         "incremental",     "--full and --incremental cannot be used together."),
    ("full",         "resume",          "--full starts a complete assessment; --resume continues a checkpoint. Pick one."),
    ("rebuild",      "incremental",     "--rebuild discards all prior state; --incremental requires it. Pick one."),
    ("rebuild",      "resume",          "--rebuild wipes the checkpoint file; --resume needs it. Pick one."),
    ("rerender",     "full",            "--rerender re-renders the existing assessment; --full rebuilds it. Pick one."),
    ("rerender",     "incremental",     "--rerender reuses Stage-1 outputs; --incremental re-analyzes a delta. Pick one."),
    ("rerender",     "rebuild",         "--rerender reuses existing artifacts; --rebuild wipes them. Pick one."),
    ("rerender",     "resume",          "--rerender starts a fresh render; --resume continues a checkpoint. Pick one."),
    ("architect_review", "no_architect_review", "--architect-review and --no-architect-review cannot be used together."),
    ("quick",        "thorough",        "--quick and --thorough cannot be used together."),
    ("enrich_arch",  "no_enrich_arch",  "--enrich-arch and --no-enrich-arch cannot be used together."),
    ("abuse_cases",  "no_abuse_cases",  "--abuse-cases and --no-abuse-cases cannot be used together."),
]


def detect_conflicts(ns: argparse.Namespace) -> Optional[str]:
    for a, b, msg in CONFLICT_PAIRS:
        if getattr(ns, a, False) and getattr(ns, b, False):
            return msg
    slug = getattr(ns, "slug", None)
    # "__auto__" is the bare-flag sentinel (random slug generated at resolve
    # time) — only an explicit user value is validated for filename-safety.
    if slug is not None and slug != "__auto__" and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", slug):
        return ("--slug must be 1-64 filename-safe characters "
                "([A-Za-z0-9._-]); got: " + repr(slug))
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
        return {"check_requirements": False,
                "requirements_url_override": None,
                "requirements_label": "disabled (--no-requirements)"}
    if ns.requirements is not None:
        return {"check_requirements": True,
                "requirements_url_override": ns.requirements or None,
                "requirements_label": (
                    f"enabled (--requirements {ns.requirements})"
                    if ns.requirements else "enabled (--requirements)"
                )}
    if config_enabled:
        return {"check_requirements": True,
                "requirements_url_override": None,
                "requirements_label": "enabled (config)"}
    return {"check_requirements": False,
            "requirements_url_override": None,
            "requirements_label": "disabled (config)"}


def resolve_assessment_depth(ns: argparse.Namespace) -> dict:
    depth = ns.assessment_depth or "standard"
    params = DEPTH_PARAMS[depth]
    label = (f"{depth} (components: criteria-selected, STRIDE turns: "
             f"{params['simple']}/{params['moderate']}/{params['complex']}, "
             f"diagrams: {params['diagrams']}, QA: {params['qa_label']})")
    return {
        "assessment_depth":      depth,
        "max_stride_components": STRIDE_COMPONENT_CEILING,
        "stride_turns_simple":   params["simple"],
        "stride_turns_moderate": params["moderate"],
        "stride_turns_complex":  params["complex"],
        "diagram_depth":         params["diagrams"],
        "qa_depth":              params["qa"],
        "max_repair_iterations": params["max_repair_iterations"],
        "depth_label":           label,
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
        raise SystemExit("Error: APPSEC_STRIDE_CONCURRENCY must be an integer between 1 and 32") from exc
    if not 1 <= value <= STRIDE_DISPATCH_CONCURRENCY_MAX:
        raise SystemExit("Error: APPSEC_STRIDE_CONCURRENCY must be between 1 and 32")
    return {"stride_concurrency": value}


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
    Stage 1c. ``--abuse-cases`` forces it on at any depth (incl. quick);
    ``--no-abuse-cases`` forces it off at any depth (incl. standard/thorough).
    The two flags are mutually exclusive (see ``CONFLICT_PAIRS``).
    """
    if getattr(ns, "no_abuse_cases", False):
        return {"skip_abuse_case_verification": True,
                "abuse_case_label": "skipped (--no-abuse-cases)"}
    if getattr(ns, "abuse_cases", False):
        return {"skip_abuse_case_verification": False,
                "abuse_case_label": "enabled (--abuse-cases)"}
    if depth == "quick":
        return {"skip_abuse_case_verification": True,
                "abuse_case_label": "skipped (auto - quick depth)"}
    return {"skip_abuse_case_verification": False,
            "abuse_case_label": "enabled"}


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
# (skill_watchdog.py: stride-stale 900s, per-component
# timeout 480s) bounds any cold-cache hang instead of pre-emptively dropping
# attack surface. Cost is controlled by the tier, not by blind spots.
LARGE_REPO_SOURCE_FILE_THRESHOLD = 400

# Orchestrator (session-model) recommendation threshold — DISTINCT from and much
# higher than LARGE_REPO_SOURCE_FILE_THRESHOLD above (which only flags "longer run").
# The orchestrator holds the largest resident context; on a *very* large repo a
# small-window session model (Sonnet 4.6 in the harness) risks mid-run compaction,
# which can drop finalization steps. At/above this source-file count we RECOMMEND the
# large-window Sonnet 5 as the SESSION model (higher cost, for more compaction
# headroom); below it we recommend Sonnet 4.6 (much cheaper, only very limited
# orchestrator benefit). Advisory only — the user always chooses (see the
# interactive prompt in SKILL-impl.md).
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
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".go", ".java", ".kt", ".rb", ".php",
    ".cs", ".rs", ".swift", ".scala", ".cpp", ".c", ".h",
)


def _count_source_files(repo_root: Path) -> int:
    """Count tracked source files via git ls-files. Returns 0 on any error.

    Cheap (one subprocess) and bounded (timeout 5 s). Falls back to 0 — which
    skips the cap heuristic — rather than failing the resolution.
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True, text=True, timeout=5,
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


def resolve_repo_size_cap(cfg: dict, repo_root: Path) -> dict:
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
    src_count = _count_source_files(repo_root)
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
        f"large repo: {src_count} source files → longer run expected, "
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


def _same_model(a: str, b: str) -> bool:
    """Loose model-id equality (tolerates date suffixes / alias vs id)."""
    a, b = (a or "").strip(), (b or "").strip()
    if not a or not b:
        return False
    return a == b or a.startswith(b) or b.startswith(a)


def recommend_orchestrator_model(src_count: int) -> dict:
    """Advisory session-model recommendation from repo source-file count.

    The orchestrator = the CC session model; the plugin cannot switch it. This
    only RECOMMENDS — the skill surfaces it and the user chooses (a divergent
    choice needs a session restart because a running loop cannot change its own
    model). Recommends Sonnet 5 only for *very* large repos (window safety);
    otherwise Sonnet 4.6 (much cheaper, only very limited orchestrator benefit).
    """
    if src_count >= ORCHESTRATOR_SONNET5_FILE_THRESHOLD:
        model = "claude-sonnet-5"
        reason = (
            f"very large repo ({src_count} source files >= "
            f"{ORCHESTRATOR_SONNET5_FILE_THRESHOLD}) — the orchestrator accumulates a "
            f"large resident context; Sonnet 5's larger window reduces the risk of "
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
            f"size, and its window is sufficient here (Sonnet 5 is recommended once a "
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

    label = (f"{mode} (STRIDE: {models['stride']}, "
             f"triage: {models['triage']}, merger: {models['merger']})")
    return {
        "reasoning_model": mode,
        "stride_model":    models["stride"],
        "triage_model":    models["triage"],
        "merger_model":    models["merger"],
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
        # (Sonnet 5) at standard AND thorough, cheapest 4.6 only at the quick tier.
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
        "recon_scanner":    "APPSEC_RECON_SCANNER_MODEL",
        "qa_routine":       "APPSEC_QA_ROUTINE_MODEL",
        "qa_content":       "APPSEC_QA_CONTENT_MODEL",
        "config_scanner":   "APPSEC_CONFIG_SCANNER_MODEL",
        "orchestrator":     "APPSEC_ORCHESTRATOR_MODEL",
        "renderer":         "APPSEC_RENDERER_MODEL",
        "abuse_verifier":   "APPSEC_ABUSE_VERIFIER_MODEL",
        "evidence_verifier": "APPSEC_EVIDENCE_VERIFIER_MODEL",
    }
    for k, env in env_map.items():
        if os.environ.get(env):
            models[k] = os.environ[env]

    return {
        "context_resolver_model": models["context_resolver"],
        "recon_scanner_model":    models["recon_scanner"],
        "qa_routine_model":       models["qa_routine"],
        "qa_content_model":       models["qa_content"],
        "config_scanner_model":   models["config_scanner"],
        "orchestrator_model":     models["orchestrator"],
        "renderer_model":         models["renderer"],
        "abuse_verifier_model":   models["abuse_verifier"],
        "evidence_verifier_model": models["evidence_verifier"],
    }


_OPUS_TOKEN = "opus"   # matches "opus", "opus-cheap", "claude-opus-4-7"
_MODEL_FIELDS = (
    "stride_model", "triage_model", "merger_model",
    "architect_model", "orchestrator_model",
    "context_resolver_model", "recon_scanner_model",
    "qa_routine_model", "qa_content_model", "config_scanner_model",
    "renderer_model", "abuse_verifier_model",
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


def resolve_stride_profile(
    reasoning_mode: str, depth: str, stride_cap: int | None = None
) -> dict:
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
    depth and only trim the High/Medium/Low tail per STRIDE category per
    component. The default (None) preserves the documented "standard =
    full STRIDE, reduction opt-in only" invariant. CRITICAL-SAFE: the
    analyzer never drops a Critical to honour the cap (see
    ``agents/appsec-stride-analyzer.md`` cap table). The cap is key-gated
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
            profile["stride_profile_label"] = (
                f"quick (depth-reduced via sonnet-economy, per-category cap {cap})"
            )
        return {"stride_profile": profile}
    if cap is not None:
        return {"stride_profile": {
            "max_threats_per_category": cap,
            "stride_profile_label": f"full (per-category cap {cap})",
        }}
    return {"stride_profile": {"stride_profile_label": "full"}}


def resolve_skip_attack_paths_authoring(depth: str) -> dict:
    """Skip the LLM-authored ``security-posture-attack-paths.json`` fragment
    at quick depth.

    The renderer's ``_derive_attack_paths_fallback`` (compose_threat_model.py)
    produces a deterministic CWE→class assignment when the fragment is
    missing. The fallback omits LLM-judgement fields (architectural root
    causes, attack chains) but preserves the heatmap structure and per-class
    finding lists — adequate for quick triage and saves ~1-3 min in Stage 2.

    No CLI override — users who want the authored fragment at quick can
    work around by running at standard depth instead. Standard and thorough
    keep authoring on.
    """
    if depth == "quick":
        return {"skip_attack_paths_authoring": True,
                "skip_attack_paths_authoring_label":
                    "skipped (quick depth — deterministic fallback)"}
    return {"skip_attack_paths_authoring": False,
            "skip_attack_paths_authoring_label":
                "authored (LLM)"}


def resolve_enrich_arch_fragments(ns: argparse.Namespace, depth: str,
                                   dry_run: bool) -> dict:
    """LLM enrichment of the security-architecture.md fragment (§7).

    Note (2026-06): architecture-diagrams.md (§2) is NOT enriched — it is
    deterministic and the skill force-regenerates it from threat-model.yaml
    before AND after Stage 2, so any LLM edit was always discarded. §2 incl.
    its per-diagram ``**Key takeaway:**`` lines is owned by
    ``pregenerate_fragments.py:gen_architecture_diagrams``. This flag now
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
        return {"enrich_arch_fragments": False,
                "enrich_arch_label": "disabled (dry-run)"}
    if getattr(ns, "no_enrich_arch", False):
        return {"enrich_arch_fragments": False,
                "enrich_arch_label": "disabled (--no-enrich-arch)"}
    if getattr(ns, "enrich_arch", False):
        return {"enrich_arch_fragments": True,
                "enrich_arch_label": "enabled (--enrich-arch)"}
    if depth == "quick":
        return {"enrich_arch_fragments": False,
                "enrich_arch_label": "disabled (default at quick depth)"}
    if depth == "standard":
        return {"enrich_arch_fragments": True,
                "enrich_arch_label": "enabled (default at standard depth)"}
    return {"enrich_arch_fragments": True,
            "enrich_arch_label": "enabled (auto-thorough)"}


def resolve_architect_review(ns: argparse.Namespace, depth: str,
                              dry_run: bool) -> dict:
    """Auto-enable at thorough, off at quick/standard. Dry-run force-off."""
    if dry_run:
        return {"architect_review": False, "architect_model": None,
                "architect_label": "disabled (dry-run)"}
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
        return {"architect_review": False, "architect_model": None,
                "architect_label": f"disabled ({trigger})"}

    # Model resolution — default opus when on; the flag overrides with a tier
    # alias (sonnet|opus) OR an explicit version id (claude-sonnet-5, …), passed
    # through verbatim — same contract as the APPSEC_ARCHITECT_MODEL env var
    # below. --no-opus still clamps any Opus id to Sonnet in apply_opus_ban().
    model = ns.architect_model or "opus"
    if os.environ.get("APPSEC_ARCHITECT_MODEL"):
        model = os.environ["APPSEC_ARCHITECT_MODEL"]

    short = model.replace("claude-", "")
    label = f"enabled ({short}, {trigger})"
    return {"architect_review": True, "architect_model": model,
            "architect_label": label}


def resolve_paths(ns: argparse.Namespace, dry_run: bool) -> dict:
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
                capture_output=True, text=True, timeout=5,
            )
            repo_root = Path(r.stdout.strip()) if r.returncode == 0 and r.stdout else repo_in
        except (OSError, subprocess.SubprocessError):
            repo_root = repo_in

    if dry_run:
        import tempfile
        output_dir = Path(tempfile.mkdtemp(prefix="appsec-dry-run-"))
    elif ns.output:
        output_dir = Path(ns.output).resolve()
    else:
        output_dir = repo_root / "docs" / "security"

    output_dir.mkdir(parents=True, exist_ok=True)

    output_outside_repo = not _is_within(output_dir, repo_root)

    return {
        "repo_root":           str(repo_root),
        "output_dir":          str(output_dir),
        "output_outside_repo": output_outside_repo,
    }


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def resolve_incremental_mode(ns: argparse.Namespace, output_dir: Path,
                              dry_run: bool,
                              cur_check_requirements: Optional[bool] = None) -> dict:
    """Detect baseline state + apply the first-match-wins rules.

    Returns a dict with ``mode``, ``mode_label``, ``incremental``,
    ``rebuild``, and an optional ``post_summary_note``. The skill layer
    prints the note after the Configuration Summary.
    """
    if dry_run:
        return {
            "mode":             "full",
            "mode_label":       "full (dry-run)",
            "incremental":      False,
            "rebuild":          False,
            "baseline_state":   _detect_baseline_state(output_dir),
            "post_summary_note": None,
        }

    state = _detect_baseline_state(output_dir)

    # Rule 0a: --rerender — re-render Stage 2 + re-QA from the EXISTING Stage-1
    # artifacts on disk. Skips Stage 1 entirely and the incremental no-op gate
    # (both handled in the skill's rerender branch). Requires a structured
    # baseline; it never re-analyzes source, so it is the wrong tool when code
    # changed (the skill prints that guidance).
    if ns.rerender:
        if state == "empty":
            raise SystemExit(
                f"Error: --rerender requires an existing assessment at "
                f"{output_dir}.\n  No threat-model.yaml found — run a full or "
                f"standard assessment first; --rerender then re-renders it from "
                f"the existing Stage-1 fragments."
            )
        return {
            "mode":             "rerender",
            "mode_label":       "rerender (re-render existing fragments + QA)",
            "incremental":      False,
            "rebuild":          False,
            "rerender":         True,
            "baseline_state":   state,
            "post_summary_note": None,
        }

    # Rule 0: --rebuild short-circuits.
    if ns.rebuild:
        note = None
        if state in ("structured", "legacy"):
            note = (f"Warning: existing threat model, cache, and changelog "
                    f"history at {output_dir} will be deleted before the run. "
                    "Audit logs (.agent-run.log, .hook-events.log) are preserved.")
        return {
            "mode":             "rebuild",
            "mode_label":       "rebuild (fresh — prior model and history discarded)",
            "incremental":      False,
            "rebuild":          True,
            "baseline_state":   state,
            "post_summary_note": note,
        }

    # Rule 1: --full.
    if ns.full:
        note = None
        if state in ("structured", "legacy"):
            note = (f"Warning: existing threat model at {output_dir} will be "
                    "overwritten. Changelog history is preserved; a Change "
                    "Summary will be printed after the run.")
        return {
            "mode":             "full",
            "mode_label":       "full (--full)",
            "incremental":      False,
            "rebuild":          False,
            "baseline_state":   state,
            "post_summary_note": note,
        }

    # Rules 2/3: --incremental.
    if ns.incremental:
        if state == "empty":
            raise SystemExit(
                f"Error: --incremental requires an existing threat model at "
                f"{output_dir}.\n  No threat-model.yaml or threat-model.md "
                f"found.\n  Run without flags (or with --full) to create an "
                f"initial threat model first."
            )
        if state == "legacy":
            raise SystemExit(
                f"Error: --incremental requires a structured baseline "
                f"(threat-model.yaml), but\n       only a legacy "
                f"threat-model.md was found at {output_dir}.\n       This "
                f"report was generated before incremental mode was "
                f"supported.\n  Fix: run once without --incremental to "
                f"bootstrap threat-model.yaml, then\n       subsequent runs "
                f"will automatically use incremental mode."
            )
        return {
            "mode":             "incremental",
            "mode_label":       "incremental (--incremental)",
            "incremental":      True,
            "rebuild":          False,
            "baseline_state":   state,
            "post_summary_note": None,
        }

    # Rule 5/6/7: no flag.
    if state == "structured":
        # Depth-increase override. The baseline records the assessment_depth it
        # was generated at (threat-model.yaml meta). If the user now asks for a
        # DEEPER depth (quick → standard → thorough), auto-incremental is the
        # wrong mode even on an unchanged repo: incremental only re-analyzes
        # changed files, so the deeper analysis would never reach the
        # carried-forward components. Force a full re-assessment so the new
        # depth applies to every component. A SAME-or-SHALLOWER depth keeps the
        # normal auto-incremental (nothing new to deepen).
        cur_depth = ns.assessment_depth or "standard"
        base_depth, _src = _extract_baseline_assessment_depth(output_dir)
        if base_depth is not None and _depth_increased(cur_depth, base_depth):
            return {
                "mode":              "full",
                "mode_label":        f"full (depth increased: {base_depth} → {cur_depth})",
                "incremental":       False,
                "rebuild":           False,
                "baseline_state":    state,
                # Auto-upgraded full (user did not type --full): the repo is
                # unchanged, only the requested depth deepened. Eligible to reuse
                # the prior recon if the tree is git-provably clean — the recon
                # gate enforces that with check-fingerprint --require-clean-tree.
                "reuse_recon_eligible": True,
                "depth_upgrade_reason": (
                    f"existing model was built at '{base_depth}' depth; "
                    f"--assessment-depth {cur_depth} requested — incremental cannot "
                    f"deepen carried-forward components, so a full re-assessment runs"
                ),
                "post_summary_note": (
                    f"Assessment depth increased ({base_depth} → {cur_depth}); running a "
                    f"full scan so the deeper analysis applies to every component "
                    f"(incremental would only re-scan changed files)."
                ),
            }
        # Requirements-toggle override (Variante B — compares the FINAL resolved
        # check_requirements, so a quick-depth auto-disable counts as a real
        # toggle). The baseline records whether it was built against security
        # requirements (meta.check_requirements). Incremental only re-analyzes
        # changed files, so it can neither add requirement tags to
        # carried-forward components when requirements are newly requested, nor
        # cleanly strip the requirement enrichment baked into carried-forward
        # threats when requirements are switched off. Two asymmetric outcomes:
        #   - requirements ADDED (off → on): additive + explicit intent
        #     (--requirements). Auto-upgrade to a full re-assessment so every
        #     component gets requirement coverage; just inform the user.
        #   - requirements DROPPED (on → off): destructive — overwrites the
        #     requirements-enriched model and silently strips the §7b/§10
        #     traceability. The off state is often the default, so this is
        #     easily hit by accident. Hard-stop and require an explicit --full
        #     to consent to overwriting the existing model.
        # Explicit --incremental bypasses this (handled above, Rule 2/3) — the
        # same honor-the-explicit-flag contract as the depth-increase override.
        if cur_check_requirements is not None:
            base_req = _extract_baseline_check_requirements(output_dir)
            if base_req is not None and base_req != cur_check_requirements:
                if cur_check_requirements and not base_req:
                    return {
                        "mode":              "full",
                        "mode_label":        "full (requirements added — model rebuilt against security requirements)",
                        "incremental":       False,
                        "rebuild":           False,
                        "baseline_state":    state,
                        # Auto-upgraded full (user did not type --full): repo
                        # unchanged, only --requirements newly requested. Eligible
                        # to reuse prior recon when the tree is git-provably clean.
                        "reuse_recon_eligible": True,
                        "mode_upgraded_reason": (
                            "existing model was built WITHOUT a security-requirements "
                            "check; --requirements now requested — incremental cannot "
                            "add requirement coverage to carried-forward components, "
                            "so a full re-assessment runs"
                        ),
                        "post_summary_note": (
                            "Security requirements were newly requested; running a "
                            "full scan so the requirements check applies to every "
                            "component (incremental would only re-scan changed files)."
                        ),
                    }
                raise SystemExit(
                    f"Error: the existing threat model at {output_dir} was built "
                    f"WITH a security-requirements check, but this run has "
                    f"requirements disabled.\n"
                    f"  An incremental scan cannot remove the requirements "
                    f"enrichment baked into carried-forward findings — it would "
                    f"silently drop the Requirements Compliance section (§7b / §10 "
                    f"traceability) while leaving stale requirement tags on "
                    f"unchanged threats.\n"
                    f"  Fix: re-run with --full to overwrite the existing model "
                    f"without requirements (changelog history is preserved), or "
                    f"pass --requirements to keep the compliance coverage."
                )
        return {
            "mode":             "incremental",
            "mode_label":       "incremental (auto)",
            "incremental":      True,
            "rebuild":          False,
            "baseline_state":   state,
            "post_summary_note": "Tip: pass --full to force a complete re-assessment.",
        }
    if state == "legacy":
        return {
            "mode":             "full",
            "mode_label":       "full (bootstrap — legacy threat-model.md detected)",
            "incremental":      False,
            "rebuild":          False,
            "baseline_state":   state,
            "post_summary_note": (
                "Legacy threat-model.md found but no structured baseline "
                "(threat-model.yaml). Bootstrapping yaml now — the next run "
                "will automatically be incremental."
            ),
        }
    # empty
    return {
        "mode":             "full",
        "mode_label":       "full (first run)",
        "incremental":      False,
        "rebuild":          False,
        "baseline_state":   state,
        "post_summary_note": None,
    }


def _detect_baseline_state(output_dir: Path) -> str:
    """Mirror of SKILL.md "Baseline detection — two distinct states"."""
    if (output_dir / "threat-model.yaml").is_file():
        return "structured"
    if (output_dir / "threat-model.md").is_file():
        return "legacy"
    return "empty"


# Ordered shallow → deep. A higher rank means more analysis (STRIDE turn budget,
# diagram + QA depth). Only an INCREASE in rank forces a full re-assessment over
# an existing model; same-or-shallower keeps auto-incremental.
_DEPTH_RANK = {"quick": 0, "standard": 1, "thorough": 2}


def _depth_increased(current: str, baseline: str) -> bool:
    """True iff ``current`` depth is strictly deeper than ``baseline``.

    Unknown depth strings rank as ``standard`` (the default) so a malformed or
    future label never silently forces or suppresses an upgrade.
    """
    cur = _DEPTH_RANK.get((current or "standard").strip().lower(), 1)
    base = _DEPTH_RANK.get((baseline or "standard").strip().lower(), 1)
    return cur > base


def _extract_baseline_assessment_depth(output_dir: Path) -> tuple[Optional[str], str]:
    """Return (assessment_depth, source) for the prior baseline.

    Reads ``meta.assessment_depth`` from the committed ``threat-model.yaml``
    (the authoritative baseline; written by build_threat_model_yaml). Mirrors
    baseline_state._extract_baseline_analysis_version: a simple root-aligned
    line match avoids pulling in pyyaml for one string field. Returns
    (None, "missing") when no depth is recorded (pre-depth baselines) so the
    caller treats it as "unknown — do not force an upgrade".
    """
    yaml_path = output_dir / "threat-model.yaml"
    if yaml_path.is_file():
        try:
            text = yaml_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        m = re.search(r"(?m)^\s{2}assessment_depth:\s*\"?(\w+)\"?\s*$", text)
        if m:
            return (m.group(1), "threat-model.yaml")
    return (None, "missing")


def _extract_baseline_check_requirements(output_dir: Path) -> Optional[bool]:
    """Return ``meta.check_requirements`` (bool) from the prior baseline.

    Reads the committed ``threat-model.yaml``. Mirrors
    _extract_baseline_assessment_depth: a root-aligned line match avoids
    pulling in pyyaml for one boolean. Returns None when the field is absent
    (pre-feature baselines) so the caller treats it as "unknown — do not gate".
    """
    yaml_path = output_dir / "threat-model.yaml"
    if yaml_path.is_file():
        try:
            text = yaml_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        m = re.search(r"(?m)^\s{2}check_requirements:\s*(true|false)\b", text)
        if m:
            return m.group(1) == "true"
    return None


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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="resolve_config.py",
        description="Resolve create-threat-model flags into a structured JSON.",
        add_help=False,  # the skill handles --help itself
    )
    # YAML
    p.add_argument("--yaml",        action="store_true")
    p.add_argument("--no-yaml",     action="store_true")
    # SARIF / pentest / requirements
    p.add_argument("--sarif",       action="store_true")
    p.add_argument("--pentest-tasks", action="store_true")
    p.add_argument("--pentest-format", choices=("generic", "strix"), default="generic")
    p.add_argument("--pentest-target", default=None)
    # --requirements optionally takes a URL; use nargs='?' so both
    # "--requirements" and "--requirements https://…" work.
    p.add_argument("--requirements", nargs="?", const="", default=None)
    p.add_argument("--no-requirements", action="store_true")
    # Deprecated aliases
    p.add_argument("--with-requirements",   action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--ignore-requirements", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--requirements-url",    default=None,
                   help=argparse.SUPPRESS)
    # Run-mode
    p.add_argument("--dry-run",   action="store_true")
    p.add_argument("--resume",    action="store_true")
    p.add_argument("--incremental", action="store_true")
    p.add_argument("--full",      action="store_true")
    p.add_argument("--rebuild",   action="store_true")
    p.add_argument("--rerender",  action="store_true")
    p.add_argument("--keep-runtime-files", action="store_true")
    p.add_argument("--verbose",   action="store_true")
    p.add_argument("--quiet",     action="store_true",
                   help="Compact console summary — print only the essentials "
                        "(repository, run, results, outputs, warnings); omit the "
                        "verdict, change summary, next steps, and run statistics.")
    # Tracing default flipped to ON in M3.6 (was opt-in pre-M3.6). Per-agent
    # token / turn / cost / wall-time tracking writes to .appsec-trace.log
    # — small file (~10 KB / run), zero token cost, materially better
    # diagnostics. ``--no-tracing`` opts out for environments that prefer
    # not to maintain the trace artifact (CI without log-retention budget,
    # privacy-restricted pipelines).
    p.add_argument("--tracing",    dest="tracing", action="store_true",
                   default=True,
                   help="Record per-agent token/cost/timing to .appsec-trace.log "
                        "(default: ON since M3.6).")
    p.add_argument("--no-tracing", dest="tracing", action="store_false",
                   help="Disable tracing — skips .appsec-trace.log creation.")
    # Paths
    p.add_argument("--repo",   default=None)
    p.add_argument("--output", default=None)
    # Models / depth
    p.add_argument("--reasoning-model",
                   choices=("sonnet", "opus-cheap", "opus",
                            "sonnet-economy", "haiku-economy"))  # haiku-economy: deprecated alias
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
    _model_help = ("Tier alias (sonnet|opus) or explicit version id "
                   "(e.g. claude-sonnet-5, claude-sonnet-4-6). Overrides the "
                   "--reasoning-model tier for this stage only.")
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
    p.add_argument("--no-opus", action="store_true", dest="no_opus",
                   help="Forbid Opus anywhere; downgrade every Opus model "
                        "selection to Sonnet. Also settable via org-profile "
                        "policy.disable_opus or env APPSEC_DISABLE_OPUS=1.")
    p.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"))
    # Convenience shortcuts: --quick / --thorough for the two non-default
    # depth levels. Mapped to --assessment-depth in resolve() below.
    # Mutually exclusive with --assessment-depth and with each other —
    # detect_conflicts() raises on collision.
    p.add_argument("--quick",    action="store_true",
                   help="Shortcut for --assessment-depth quick.")
    p.add_argument("--thorough", action="store_true",
                   help="Shortcut for --assessment-depth thorough.")
    # Opt-in per-category STRIDE threat cap (cost lever). OFF by default — the
    # full STRIDE depth at standard/thorough is preserved unless this is set.
    p.add_argument("--stride-cap", type=int, default=None, metavar="N",
                   help="Opt-in: keep at most N threats per STRIDE category per "
                        "component (Critical-safe — Criticals are never dropped). "
                        "Trims the High/Medium/Low tail to cut tokens/cost; the "
                        "rest of full depth (CVSS, evidence, verification greps) "
                        "stays intact. Off by default.")
    p.add_argument("--evidence-verifier-cap", type=int, default=None, metavar="N",
                   help="Verify at most N non-Critical findings in Phase 10a; "
                        "Critical findings do not count toward the cap. Defaults: 20 "
                        "(quick), 30 (standard), 100 (thorough).")
    # Architect
    p.add_argument("--architect-review",   action="store_true")
    p.add_argument("--no-architect-review", action="store_true")
    p.add_argument("--architect-model", default=None, metavar="MODEL",
                   help="Tier alias (sonnet|opus) or explicit version id for the "
                        "architect reviewer. --no-opus clamps any Opus id to Sonnet.")
    # Architecture-fragment enrichment (M3.3 / D2). On by default at standard
    # and thorough; off at quick since 2026-05.
    p.add_argument("--no-enrich-arch", action="store_true",
                   dest="no_enrich_arch",
                   help="Disable LLM enrichment of the security-architecture.md "
                        "(§7) fragment (on by default at standard/thorough). "
                        "architecture-diagrams.md/§2 is always deterministic.")
    p.add_argument("--enrich-arch", action="store_true",
                   dest="enrich_arch",
                   help="Force LLM enrichment of the security-architecture.md "
                        "(§7) fragment at any depth (overrides the quick-depth "
                        "default-off).")
    # v2 13-section §7 layout — the only supported layout.
    # `--schema-v2` is kept as a no-op alias so explicit declarations in
    # CI scripts do not break. `--schema-v1` is accepted by the parser only
    # to return a clear removal error instead of "unrecognized argument".
    p.add_argument("--schema-v2", action="store_true",
                   dest="schema_v2",
                   help="Explicitly request the 13-section §7 security "
                        "architecture layout. No-op because v2 is the only "
                        "supported schema.")
    p.add_argument("--schema-v1", action="store_true",
                   dest="schema_v1",
                   help="Removed legacy option. Schema v2 is the only "
                        "supported §7 layout.")
    # Walkthroughs opt-out (2026-05). Stage 2 normally authors
    # `attack-walkthroughs.md` (sequence diagrams per Critical) — costs
    # ~1 min in quick depth, more in thorough. Skipping renders §3 with
    # the deterministic chain-overview only, no per-finding sequence
    # diagrams. Useful for CI / regression / fast iteration.
    p.add_argument("--no-walkthroughs", action="store_true",
                   dest="no_walkthroughs",
                   help="Skip authoring attack-walkthroughs.md in Stage 2; "
                        "§3 falls back to chain-overview-only rendering.")
    # Abuse-case verification gating (2026-06). Stage 1c runs a deterministic
    # matcher + per-candidate verifier fan-out that confirms attack chains and
    # can elevate keystone findings. ON by default at standard/thorough; the
    # quick fast-mode skips it. --abuse-cases forces it on at any depth;
    # --no-abuse-cases forces it off at any depth. Mutually exclusive
    # (detect_conflicts()).
    p.add_argument("--abuse-cases", action="store_true", dest="abuse_cases",
                   help="Force abuse-case verification ON at any depth "
                        "(overrides the quick-depth default-off).")
    p.add_argument("--no-abuse-cases", action="store_true", dest="no_abuse_cases",
                   help="Force abuse-case verification OFF at any depth "
                        "(skip the Stage 1c verifier fan-out even at "
                        "standard/thorough).")
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
    p.add_argument("--register-severity-floor",
                   dest="register_severity_floor",
                   choices=("critical", "high", "medium", "low", "informational"),
                   default=None,
                   help="Drop threats below this severity from the canonical "
                        "register and every downstream count. Default 'medium' "
                        "(Low/Informational excluded — they are noise in a "
                        "threat model). Pass 'low' to keep Low findings.")
    # PR / base / no-qa / qa-scan-repo
    p.add_argument("--base",         default=None)
    p.add_argument("--pr-mode",      action="store_true")
    p.add_argument("--no-qa",        action="store_true")
    p.add_argument("--qa-scan-repo", action="store_true")
    # Scan manifest — log all scanned files to OUTPUT_DIR/.scan-manifest.txt
    p.add_argument("--scan-manifest", action="store_true")
    # Optional model slug — when set, the run additionally emits a
    # postfix-stamped, copy-ready deliverable set (threat-model-<slug>.md /
    # .yaml / .figure*.svg / …) so several models can share one directory
    # without overwriting each other. Default None = canonical names only.
    p.add_argument("--slug", nargs="?", const="__auto__", default=None,
                   help="Postfix for an additional copy-ready deliverable set "
                        "(threat-model-<slug>.*). Bare --slug generates a "
                        "random one; --slug <value> uses it. Default: none.")
    # Suppress interactive confirmation prompts (auto-accept current mode).
    p.add_argument("--no-confirm", "--yes", action="store_true",
                   dest="no_confirm",
                   help="Skip interactive confirmation prompts; accept auto-detected mode.")
    # M11 — wall-time hard deadline. Skill watchdog checks the elapsed seconds
    # since ASSESSMENT_START_EPOCH and aborts the in-flight Stage 1/2/3/4
    # Agent dispatch via TaskStop when reached. Format accepts plain seconds
    # ("3600"), minutes ("60m"), or hours ("1h"). Default unset = no deadline.
    p.add_argument("--max-wall-time", type=str, default=None,
                   metavar="DURATION",
                   help="Hard wall-time deadline (e.g. 3600, 60m, 1h). "
                        "Skill watchdog aborts the run when reached. "
                        "Default: unbounded.")
    # M9 — cost budget hard cap (USD). Skill watchdog scans .hook-events.log
    # for cumulative cost and aborts when reached.
    p.add_argument("--max-cost", type=float, default=None,
                   metavar="USD",
                   help="Hard cost cap in USD (e.g. 15.0). Skill watchdog "
                        "aborts the run when cumulative cost exceeds this. "
                        "Default: unbounded.")
    # Negative flags for tri-state semantics. When org profiles set output
    # defaults via a preset, the user needs an explicit way to opt back
    # out without selecting a different preset. ``--sarif`` still wins over
    # ``--no-sarif`` (positive overrides negative) for compatibility with
    # the existing direct-flag-wins precedence.
    p.add_argument("--no-sarif", action="store_true", dest="no_sarif",
                   help="Disable SARIF export even if a preset enables it.")
    p.add_argument("--no-pentest-tasks", action="store_true", dest="no_pentest_tasks",
                   help="Disable pentest-tasks export even if a preset enables it.")
    p.add_argument("--no-pdf", action="store_true", dest="no_pdf",
                   help="Disable PDF export even if a preset enables it.")

    # Org-profile selection flags. These are consumed by resolve_org_profile.
    # The resolver merges the resulting defaults below CLI flags.
    # Cover-page branding. Local overrides for the org-profile `branding`
    # block; consumed by compose_threat_model.py via .skill-config.json.
    p.add_argument("--report-title", default=None,
                   help="Override the report cover title (project name is still appended).")
    p.add_argument("--contact-name", default=None,
                   help="Contact name shown in the report cover metadata.")
    p.add_argument("--contact-email", default=None,
                   help="Contact e-mail shown in the report cover metadata.")
    p.add_argument("--logo", default=None,
                   help="Cover logo: local file path or http(s) URL (staged before render).")

    p.add_argument("--org-profile", default=None,
                   help="Path to an org-profile YAML; overrides the packaged default.")
    p.add_argument("--preset", default=None,
                   help="Name of the preset to use from the active org profile.")
    p.add_argument("--no-org-profile", action="store_true",
                   help="Ignore any packaged or env-pointed org profile for this run.")

    # Skill-layer flags. The resolver itself does not act on them but
    # accepts them so ``--validate-only`` does not reject documented
    # create-threat-model invocations. The skill layer reads these
    # directly from argv.
    p.add_argument("--pdf", action="store_true",
                   help="Skill-layer flag — exports threat-model.pdf after Stage 4.")
    p.add_argument("--html", action="store_true",
                   help="Skill-layer flag — exports threat-model.html after Stage 4.")
    p.add_argument("--embed-figures", action="store_true",
                   help="Embed Figure 1 inline in threat-model.md as a base64 data: URI "
                        "(self-contained doc); figure1.svg is still written. NOTE: GitHub "
                        "strips data: URIs, so the default file reference is best for GitHub.")
    p.add_argument("--max-resumes", type=int, default=None,
                   help="Skill-layer flag — cap on Stage 1 auto-resume dispatches.")
    p.add_argument("--clean-cache", action="store_true",
                   help="Skill-layer flag — clean cache and exit.")
    p.add_argument("--clean-all", action="store_true",
                   help="Skill-layer flag — clean everything in OUTPUT_DIR and exit.")

    # Remaining positional args = scope words.
    p.add_argument("scope", nargs="*")
    # --emit-file writes to $OUTPUT_DIR/.skill-config.json
    p.add_argument("--emit-file", action="store_true")
    return p


# ---------------------------------------------------------------------------
# Full resolution — orchestrates the pieces
# ---------------------------------------------------------------------------


def resolve(argv: list[str], plugin_root: Path) -> dict:
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
            "Error: --schema-v1 was removed. Schema v2 is the only supported "
            "§7 security-architecture layout."
        )

    # Depth shortcuts: --quick / --thorough are sugar for --assessment-depth.
    # Reject collision with an explicit --assessment-depth that disagrees;
    # silently accept agreement (--quick --assessment-depth quick is fine).
    for short_attr, depth_value in (("quick", "quick"), ("thorough", "thorough")):
        if getattr(ns, short_attr, False):
            if ns.assessment_depth and ns.assessment_depth != depth_value:
                raise SystemExit(
                    f"Error: --{short_attr} conflicts with --assessment-depth "
                    f"{ns.assessment_depth}. Pick one."
                )
            ns.assessment_depth = depth_value

    # Build the resolved config by composing per-resolver outputs.
    cfg: dict[str, Any] = {
        "invocation_args": " ".join(argv),
        "scope":           ns.scope,
        "dry_run":         ns.dry_run,
        "write_sarif":     ns.sarif,
        "write_pentest_tasks": ns.pentest_tasks,
        "pentest_format":  ns.pentest_format,
        "pentest_target":  ns.pentest_target,
        "keep_runtime_files": ns.keep_runtime_files,
        "slug":            (secrets.token_hex(2) if ns.slug == "__auto__" else ns.slug),
        "verbose":         ns.verbose,
        "quiet":           ns.quiet,
        "tracing":         ns.tracing,
        "resume":          ns.resume,
        "pr_mode":         ns.pr_mode,
        "base_ref":        ns.base,
        "qa_scan_repo":    ns.qa_scan_repo,
        "scan_manifest":   ns.scan_manifest,
        "no_confirm":      ns.no_confirm,
        # Persisted to .skill-config.json so compose_threat_model.py honours it
        # on EVERY invocation (renderer, recompose, fragment-fixer) without
        # threading a CLI flag through each call site.
        "embed_figures":   bool(ns.embed_figures),
        # Cover branding. CLI value (or None) here; an active org profile may
        # fill in a None field in _apply_org_profile (CLI always wins).
        "report_title":    ns.report_title,
        "contact_name":    ns.contact_name,
        "contact_email":   ns.contact_email,
        "logo":            ns.logo,
        "write_pdf":       bool(ns.pdf),
        "write_html":      bool(ns.html),
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

    # Quick-depth post-override for requirements — force off unless the
    # user explicitly opted in via --requirements.
    if cfg["assessment_depth"] == "quick" and ns.requirements is None \
            and not ns.no_requirements:
        cfg["check_requirements"] = False
        cfg["requirements_label"] = "disabled (auto — quick depth)"

    cfg.update(resolve_reasoning_model(ns, depth_info["assessment_depth"]))
    cfg.update(resolve_extended_models(
        cfg["reasoning_model"], depth_info["assessment_depth"]
    ))
    cfg.update(resolve_stride_profile(
        cfg["reasoning_model"], depth_info["assessment_depth"],
        getattr(ns, "stride_cap", None),
    ))
    cfg.update(resolve_architect_review(
        ns, depth_info["assessment_depth"], ns.dry_run
    ))
    cfg.update(resolve_enrich_arch_fragments(
        ns, depth_info["assessment_depth"], ns.dry_run
    ))
    cfg["security_schema"] = "v2"
    cfg["security_schema_label"] = "v2 (13-section security architecture layout)"
    cfg.update(resolve_skip_attack_paths_authoring(
        depth_info["assessment_depth"]
    ))
    # Walkthroughs opt-out (2026-05). Quick depth is the fast mode and skips
    # per-finding sequenceDiagram authoring by default; standard/thorough only
    # skip it when the user passes --no-walkthroughs.
    cfg["skip_attack_walkthroughs"] = bool(
        getattr(ns, "no_walkthroughs", False) or quick_depth
    )
    if getattr(ns, "no_walkthroughs", False):
        cfg["skip_attack_walkthroughs_label"] = "skipped (--no-walkthroughs)"
    elif quick_depth:
        cfg["skip_attack_walkthroughs_label"] = "skipped (auto - quick depth)"
    else:
        cfg["skip_attack_walkthroughs_label"] = "authored (LLM)"
    cfg.update(resolve_abuse_case_verification(ns, depth_info["assessment_depth"]))
    cfg.update(resolve_paths(ns, ns.dry_run))
    # Paths are consumed as data by resolve_abuse_cases.py, which constrains
    # them to REPO_ROOT before reading. Never interpolate these values in Bash.
    cfg["abuse_case_files"] = list(ns.abuse_case_file or [])
    cfg["only_abuse_case_ids"] = list(ns.only_abuse_case or [])

    # B2c — repo-size auto-cap. Must run after resolve_paths so we have
    # the final repo_root value, and after resolve_assessment_depth so we
    # know the tier.
    cfg.update(resolve_repo_size_cap(cfg, Path(cfg["repo_root"])))

    # Orchestrator (session-model) recommendation — advisory, runs at ALL depths.
    # Surfaced in the pre-flight box and, interactively, an optional prompt
    # (SKILL-impl.md). The user always makes the final choice; a divergent choice
    # requires a session restart (a running loop cannot switch its own model).
    cfg.update(recommend_orchestrator_model(_count_source_files(Path(cfg["repo_root"]))))

    # (Removed 2026-06: the B2d large-repo reasoning-tier auto-downgrade.
    # Large repos are exactly where Opus reasoning pays off — better
    # calibration and, via lower cache-read churn, at worst cost-neutral —
    # so forcing them down to Sonnet was backwards. repo_size_capped is now
    # purely informational. See docs/analysis/plan-opus-stride-default-2026-06-21.md.)

    cfg.update(resolve_incremental_mode(
        ns, Path(cfg["output_dir"]), ns.dry_run,
        cur_check_requirements=cfg.get("check_requirements"),
    ))

    # M11 — wall-time deadline parsing. Accept "3600" (s), "60m", "1h".
    cfg["max_wall_time_seconds"] = _parse_duration(ns.max_wall_time) if ns.max_wall_time else None
    # M9 — cost budget. Plain float USD.
    cfg["max_cost_usd"] = ns.max_cost

    # Plugin metadata (always present).
    cfg["plugin_root"]   = str(plugin_root)
    cfg["plugin_version"] = _read_plugin_version(plugin_root)
    cfg["analysis_version"] = _read_analysis_version(plugin_root)

    # Org-profile resolution. Runs last so it can inspect the already-resolved
    # cfg (e.g. assessment_depth for quick_default_active rules). Direct CLI
    # flags always win — org-profile only fills in fields that were not
    # explicitly toggled by the user.
    cfg.update(_apply_org_profile(ns, cfg, plugin_root))

    # Opus ceiling — MUST be the last model step. Sourced from (CLI --no-opus)
    # OR (env APPSEC_DISABLE_OPUS) OR (org-profile policy.disable_opus, merged
    # into cfg["disable_opus"] by _apply_org_profile above). Running here —
    # after every resolver, env override, and the org merge — is what makes the
    # ceiling non-bypassable.
    disable_opus = bool(
        getattr(ns, "no_opus", False)
        or os.environ.get("APPSEC_DISABLE_OPUS", "").strip().lower()
            in ("1", "true", "yes", "on")
        or cfg.get("disable_opus")
    )
    cfg.update(apply_opus_ban(cfg, disable_opus))

    # RC.A — emit `total_stages` deterministically so the skill banner does
    # not have to compute it from prose in SKILL-impl.md. Formula:
    #   2 (Stage 1 + Stage 2)
    #   + 1 when QA runs (not SKIP_QA and not DRY_RUN)
    #   + 1 when Architect Review runs (architect_review and not DRY_RUN)
    cfg["total_stages"] = _compute_total_stages(cfg)

    # Normalise a relative local logo path (from --logo) against the current
    # working directory so compose_threat_model.py — which runs from a
    # different CWD — can resolve it. URLs and absolute paths (incl. an
    # org-profile logo already absolutised against its profile dir) are
    # unchanged.
    _logo = cfg.get("logo")
    if _logo and not str(_logo).lower().startswith(("http://", "https://")):
        _lp = Path(str(_logo)).expanduser()
        if not _lp.is_absolute():
            cfg["logo"] = str((Path.cwd() / _lp).resolve())

    # Early pre-flight status line — a single human line the skill prints as
    # response text right after extracting the resolved vars, BEFORE the slow
    # incremental pre-check / dirty-set git diffs run. It fills the otherwise
    # silent gap between the "🔧 Building …" line and the Pre-flight summary so
    # the user knows what the wait is doing (notably "existing model found,
    # computing incremental delta"). Deterministic content; the model only
    # relays it (same pattern as the LLM-typed Pre-flight summary).
    cfg["preflight_status"] = _preflight_status_line(cfg)

    return cfg


def _preflight_status_line(cfg: dict) -> str:
    """One-line early status for the pre-flight wait (see resolve())."""
    state = cfg.get("baseline_state")
    has_model = state in ("structured", "legacy")
    if cfg.get("mode") == "rebuild":
        return "🔧 Rebuilding from scratch — wiping the prior model and cache …"
    if cfg.get("rerender"):
        return "🖉 Re-rendering the report from existing analysis fragments …"
    if cfg.get("incremental") and has_model:
        return ("📋 Existing threat model found — computing the incremental "
                "delta (changed files vs. baseline) …")
    if has_model:
        return ("📋 Existing threat model found — preparing a full "
                "re-assessment …")
    return "🔍 No prior threat model — preparing a full assessment …"


def _compute_total_stages(cfg: dict) -> int:
    """RC.A — programmatic total_stages for the Stage handoff banner.

    Stays in lock-step with SKILL-impl.md §Stage 1 Handoff Banner:
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

    org_block["write_sarif"] = _resolve_bool(
        ns.sarif, ns.no_sarif, defaults.get("write_sarif"), cfg["write_sarif"]
    )
    org_block["write_pentest_tasks"] = _resolve_bool(
        ns.pentest_tasks, ns.no_pentest_tasks, defaults.get("write_pentest_tasks"),
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
    if (
        profile_rs.get("requirements_yaml_url")
        and ns.requirements is None
        and not ns.no_requirements
    ):
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
    if not ns.tracing and isinstance(defaults.get("tracing"), bool):
        org_block["tracing"] = defaults["tracing"]
    if not ns.scan_manifest and isinstance(defaults.get("scan_manifest"), bool):
        org_block["scan_manifest"] = defaults["scan_manifest"]

    # Guardrails — only apply when the user did not set the corresponding flag.
    if ns.max_wall_time is None and defaults.get("max_wall_time"):
        try:
            org_block["max_wall_time_seconds"] = _parse_duration(defaults["max_wall_time"])
        except (TypeError, ValueError):
            pass
    if ns.max_cost is None and isinstance(defaults.get("max_cost_usd"), (int, float)):
        org_block["max_cost_usd"] = float(defaults["max_cost_usd"])

    return org_block


def _load_resolve_org_profile_module(plugin_root: Path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "resolve_org_profile",
        plugin_root / "scripts" / "resolve_org_profile.py",
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
            ["python3", str(plugin_root / "scripts" / "plugin_meta.py"),
             "get", "plugin_version"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _read_analysis_version(plugin_root: Path) -> int:
    try:
        r = subprocess.run(
            ["python3", str(plugin_root / "scripts" / "plugin_meta.py"),
             "get", "analysis_version"],
            capture_output=True, text=True, timeout=5,
        )
        return int(r.stdout.strip())
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Configuration Summary (human-readable, printed by the skill)
# ---------------------------------------------------------------------------


def render_configuration_summary(cfg: dict) -> str:
    """Render the human-readable configuration block printed at skill start.

    Layout principle:
      * Group the run facts into Target / Run Plan / Active Options so the
        user sees what will be modelled before any agent dispatch.
      * Wrap every value inside a bounded box. Long paths, URLs, and scope
        text must not push the right border out of alignment.
      * Optional rows are emitted only when an option is active or deviates
        from the silent default.
    """
    lines = ["Configuration resolved.", ""]
    lines.extend(_render_summary_box(cfg))

    post_lines = _configuration_post_summary_notes(cfg)
    if post_lines:
        lines.append("")
        lines.extend(f"  {line}" for line in post_lines)

    return "\n".join(lines) + "\n"


def render_run_plan(
    cfg: dict,
    pre_check: dict | None,
    dirty_set: dict | None,
    compat_label: str | None,
    session_model: str = "",
    suppress_session_advisories: bool = False,
) -> str:
    """Render the consolidated Create-Threat-Model box, post-pre-check.

    Differs from ``render_configuration_summary`` in *what* it shows:

      * the user-facing Mode line carries the FINAL verdict the pipeline
        will act on (NO-OP / NOISE / DRIFT / DIRTY / AMBIGUOUS / FULL),
        not the raw user param.
      * the Pipeline line lists the stages that WILL ACTUALLY RUN given
        the pre-check decisions, including the SKIPPED case.
      * a "Why" section enumerates the security-relevant files that
        triggered the verdict (or the lack thereof when fast-aborting).

    ``pre_check``  — JSON dict from ``baseline_state.py check-changes``
                     (or None when no incremental pre-check ran, e.g.
                     full / rebuild / first-run).
    ``dirty_set``  — JSON dict from ``baseline_state.py dirty-set``
                     (or None when not consulted).
    ``compat_label`` — output of the analysis_version compat gate
                     ("equal" / "older-compatible" / "incompatible" /
                     "unknown" / None).
    """
    width = _summary_width()
    lines: list[str] = ["Threat Model — Pre-flight", ""]

    verdict = _run_plan_verdict(cfg, pre_check, dirty_set, compat_label)

    def kv(label: str, value: Any) -> list[str]:
        prefix = f"  {label:<10}: "
        value_width = max(20, width - len(prefix))
        chunks = wrap(
            str(value),
            width=value_width,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        out = [prefix + chunks[0]]
        cont = " " * len(prefix)
        out.extend(cont + c for c in chunks[1:])
        return out

    def bullet(text: str) -> list[str]:
        prefix = "  • "
        value_width = max(20, width - len(prefix))
        chunks = wrap(
            str(text),
            width=value_width,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        out = [prefix + chunks[0]]
        cont = " " * len(prefix)
        out.extend(cont + c for c in chunks[1:])
        return out

    # --- Section: Target ---
    lines.append("Target")
    lines.extend(kv("Repository", cfg["repo_root"]))
    lines.extend(kv("Output", cfg["output_dir"]))

    # --- Section: Plugin ---
    lines.append("")
    lines.append("Plugin")
    lines.extend(kv(
        "Version",
        f"appsec-advisor {cfg['plugin_version']} "
        f"(analysis v{cfg['analysis_version']})",
    ))
    if pre_check:
        ver = pre_check.get("plugin_version", {}) or {}
        baseline_v = ver.get("baseline")
        tier = ver.get("tier")
        if baseline_v and baseline_v != cfg["plugin_version"]:
            drift_marker = "  ⚠ DRIFT" if tier in ("minor", "major") else ""
            lines.extend(kv("Baseline", f"{baseline_v} (tier={tier}){drift_marker}"))
    if compat_label and compat_label not in ("equal", None, ""):
        lines.extend(kv("Schema", f"analysis_version drift: {compat_label}"))
    lines.extend(kv("Mode", verdict["mode_line"]))

    # --- Section: Decision ---
    lines.append("")
    lines.append("Decision")
    lines.extend(kv("Verdict", verdict["verdict"]))
    lines.extend(kv("Pipeline", verdict["pipeline"]))
    if verdict.get("reason"):
        lines.extend(kv("Reason", verdict["reason"]))

    # --- Section: Session-model cost callout (prominent — right under the
    # verdict so a pricey Opus/Sonnet-5 session is impossible to miss). ---
    if verdict.get("will_run") and not suppress_session_advisories:
        # Suppressed when the interactive orchestrator-model prompt will fire —
        # it supersedes both passive advisories (avoids saying the same thing 3×).
        cost_callout = _render_session_cost_callout(session_model)
        if cost_callout:
            lines.append("")
            lines.extend(cost_callout)
        orch_lines = _render_orchestrator_box_lines(cfg, session_model)
        if orch_lines:
            lines.append("")
            lines.extend(orch_lines)

    # --- Section: Files / Components (only when pre-check ran) ---
    if pre_check:
        sec_count = pre_check.get("security_relevant_change_count", 0)
        noise_count = len(pre_check.get("noise_only_changes", []) or [])
        excluded = pre_check.get("excluded_pre_filter_count", 0)
        total = sec_count + noise_count + excluded
        if total or sec_count or excluded:
            lines.append("")
            lines.append("Files")
            lines.extend(kv("Total seen", str(total)))
            lines.extend(kv("Excluded", f"{excluded} (plugin output / scan-excludes)"))
            lines.extend(kv("Noise", f"{noise_count} (docs / format-only / non-security)"))
            lines.extend(kv("Relevant", str(sec_count)))

        if dirty_set is not None:
            known = len(dirty_set.get("all_components_known", []) or [])
            dirty_ids = dirty_set.get("dirty_component_ids", []) or []
            carry = max(0, known - len(dirty_ids))
            lines.extend(kv(
                "Components",
                f"{known} known, {len(dirty_ids)} dirty"
                + (f" ({', '.join(dirty_ids[:5])})" if dirty_ids else "")
                + f", {carry} carried forward",
            ))

    # --- Section: Why (file list with reasons) ---
    if pre_check:
        sec_files = pre_check.get("security_relevant_changes", []) or []
        reasons = pre_check.get("relevance_reasons", {}) or {}
        if sec_files:
            lines.append("")
            lines.append(
                "Why this run is going to launch"
                if verdict["will_run"] else
                "Why this run will NOT execute Stage 1+2+3"
            )
            for f in sec_files[:6]:
                rs = reasons.get(f, [])
                rs_short = ", ".join(rs[:3]) if rs else "no reason recorded"
                lines.extend(bullet(f"{f}  [{rs_short}]"))
            if len(sec_files) > 6:
                lines.extend(bullet(f"... and {len(sec_files) - 6} more"))

        # When dirty-set returned ambiguous (potential new component),
        # surface the unmapped files so the user knows what to expect.
        if dirty_set and dirty_set.get("decision") == "ambiguous_potential_new_component":
            unmapped = dirty_set.get("unmapped_files", []) or []
            if unmapped:
                lines.append("")
                lines.append("Unmapped (possible new component)")
                for u in unmapped[:6]:
                    lines.extend(bullet(u))

    # --- Section: Configuration (only when pipeline will actually run) ---
    if verdict["will_run"]:
        lines.append("")
        lines.append("Configuration")
        lines.extend(kv("Depth", _format_depth_summary(cfg)))
        lines.extend(kv("Reasoning", _format_reasoning_summary(cfg)))
        lines.extend(kv("STRIDE cap", _format_stride_cap(cfg)))
        active = _summary_active_options(cfg)
        for label, value in active:
            lines.extend(kv(label, value))

    # --- Section: Depth tradeoff (prominent callout, above Notes) ---
    tradeoff = _render_depth_tradeoff(cfg)
    if tradeoff:
        lines.append("")
        lines.extend(tradeoff)

    # --- Section: Notes / Recommendations ---
    notes = _run_plan_notes(verdict, cfg, pre_check, dirty_set, compat_label)
    if notes:
        lines.append("")
        lines.append("Notes")
        for n in notes:
            lines.extend(bullet(n))

    return "\n".join(lines) + "\n"


def render_run_plan_notes(
    cfg: dict,
    pre_check: dict | None,
    dirty_set: dict | None,
    compat_label: str | None,
    session_model: str = "",
) -> str:
    """Render the advisory tail of the run-plan box — the session-model cost
    callout, the depth-tradeoff callout, and the Notes / Recommendations block.

    The create-threat-model skill renders the full Pre-flight banner LLM-side
    (to avoid the Bash output double-fold) but emits this tail via a
    deterministic Bash call so the cost callout + depth-vs-coverage callout
    never depend on the model re-typing them. This is the LEGACY-path surface for
    the session-model cost callout; the thin-full runtime folds the same callout
    into the box via ``render_run_plan``. Returns "" when there is nothing to
    emit so the caller can omit it.
    """
    verdict = _run_plan_verdict(cfg, pre_check, dirty_set, compat_label)
    tradeoff = _render_depth_tradeoff(cfg)
    notes = _run_plan_notes(verdict, cfg, pre_check, dirty_set, compat_label)
    cost_callout = _render_session_cost_callout(session_model) if verdict.get("will_run") else []
    if not tradeoff and not notes and not cost_callout:
        return ""
    lines: list[str] = []
    if cost_callout:
        lines.extend(cost_callout)
        if tradeoff or notes:
            lines.append("")
    if tradeoff:
        lines.extend(tradeoff)
    if notes:
        if tradeoff:
            lines.append("")
        width = _summary_width()
        prefix = "  • "
        value_width = max(20, width - len(prefix))
        lines.append("Notes")
        for n in notes:
            chunks = wrap(
                str(n),
                width=value_width,
                break_long_words=True,
                break_on_hyphens=False,
            ) or [""]
            lines.append(prefix + chunks[0])
            cont = " " * len(prefix)
            lines.extend(cont + c for c in chunks[1:])
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Effective per-agent model routing + session-model cost callout (transparency;
# needs the host session id, injected by the caller — resolve_config is blind).
# ---------------------------------------------------------------------------

# Every value-agent whose model the user cares about, in dispatch order. Each
# carries a resolved value in ``cfg`` (concrete id under sonnet-economy, or the
# bare ``sonnet`` alias otherwise). renderer + abuse_verifier default to the
# ``sonnet`` alias (host session) but are pinnable via APPSEC_RENDERER_MODEL /
# APPSEC_ABUSE_VERIFIER_MODEL. This list is the display source of truth; keep
# the user-facing rationale in docs/model-selection.md aligned with it.
_ROUTING_ROWS: list[tuple[str, str | None, str]] = [
    # (display label, cfg key or None, note)
    ("STRIDE (discovery)",       "stride_model",           "reasoning core"),
    ("Triage (severity)",        "triage_model",           "reasoning core"),
    ("Merger (dedup)",           "merger_model",           "inline unless hybrid/Opus"),
    ("Context resolver",         "context_resolver_model", "deterministic"),
    ("Recon scanner",            "recon_scanner_model",    "deterministic"),
    ("Config scanner",           "config_scanner_model",   "deterministic"),
    ("QA routine",               "qa_routine_model",       "mechanical fixes"),
    ("QA content",               "qa_content_model",       "contract reasoning"),
    ("Orchestrator (main loop)", "orchestrator_model",     "= host session"),
    ("Renderer (§7 ‖ MS)",       "renderer_model",         "follows session; pin APPSEC_RENDERER_MODEL"),
    ("Abuse-case verifier",      "abuse_verifier_model",   "follows session; pin APPSEC_ABUSE_VERIFIER_MODEL"),
]


def _session_model_advisory(session_model: str) -> str:
    """Short cost advisory keyed on the host session. Flags EVERY non-4.6 session
    (Sonnet-5 and Opus) since a Sonnet-4.6 session ~halves the cost. Empty
    (undetected) → no advisory. Informational, never a blocker."""
    s = (session_model or "").lower()
    if not s:
        return ""
    if "sonnet-4-6" in s:
        return "Sonnet-4.6 session — the cheapest setting for this skill."
    switch = (
        "Cheapest: /clear then /model claude-sonnet-4-6 (in-session — keeps the plugin "
        "loaded, no relaunch flags needed), then re-run. Fresh terminal: `claude --model "
        "claude-sonnet-4-6` PLUS the launch flags you started this session with "
        "(e.g. --plugin-dir). Buy back per stage where Sonnet-5 pays: --triage-model, "
        "APPSEC_RENDERER_MODEL, APPSEC_ABUSE_VERIFIER_MODEL."
    )
    if "opus" in s:
        return (
            "Opus session — the report/verification agents follow it and the "
            "dominant cache-read cost is billed at Opus rates. " + switch
        )
    return (
        "Non-4.6 session — a Sonnet-4.6 session is ~half the cost at the same "
        "coverage (the analysis core already runs on 4.6). " + switch
    )


def _render_session_cost_callout(session_model: str) -> list[str]:
    """Prominent ⚠/ℹ callout for the Pre-flight box: ⚠ for any non-4.6 session
    (Sonnet-5 or Opus), low-key ℹ for Sonnet-4.6, nothing when undetected."""
    advisory = _session_model_advisory(session_model)
    if not advisory:
        return []
    marker = "ℹ" if "sonnet-4-6" in session_model.lower() else "⚠"
    head = f"{marker} Session model — {session_model}"
    width = _summary_width()
    prefix = "  "
    chunks = wrap(
        advisory,
        width=max(20, width - len(prefix)),
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    return [head, *[prefix + c for c in chunks]]


def _render_orchestrator_box_lines(cfg: dict, session_model: str) -> list[str]:
    """Compact in-box orchestrator-recommendation lines for the Pre-flight box.
    Always states the repo-size-derived recommendation; adds a one-line restart
    hint only when the detected session diverges. Advisory — never binding."""
    rec = cfg.get("orchestrator_recommended_model")
    if not rec:
        return []
    files = cfg.get("orchestrator_recommendation_repo_files")
    size = "very large repo" if rec == "claude-sonnet-5" else "normal-sized repo"
    tail = f", {files} files)" if files is not None else ")"
    out = [f"Orchestrator (session) — recommend {rec}  ({size}{tail}"]
    if session_model and not _same_model(session_model, rec):
        out.append(
            f"  This session is {session_model}; switch with /clear then /model {rec} "
            f"(in-session, keeps the plugin loaded), then re-run (optional — only a "
            f"recommendation)."
        )
    return out


def _resolve_routing_value(value: str | None, session_model: str) -> str:
    """Resolve a routing cell for display. The bare ``sonnet`` alias resolves to
    the host session model; a concrete id or other tier alias is shown verbatim."""
    v = str(value or "").strip()
    if v == "sonnet":
        return session_model if session_model else "sonnet → host session (undetected)"
    return v or "(default)"


def render_effective_routing(cfg: dict, session_model: str) -> str:
    """Human-readable effective per-agent routing table, with the ``sonnet`` alias
    resolved to the detected host session version ('' when detection missed)."""
    header_session = session_model or "undetected"
    lines = [f"Effective model routing (host session: {header_session})", ""]
    resolved: list[tuple[str, str, str]] = []
    for label, key, note in _ROUTING_ROWS:
        raw = cfg.get(key) if key else "sonnet"
        resolved.append((label, _resolve_routing_value(raw, session_model), note))
    label_w = max(len(r[0]) for r in resolved)
    model_w = max(len(r[1]) for r in resolved)
    for label, model, note in resolved:
        lines.append(f"  {label:<{label_w}}  {model:<{model_w}}  {note}")
    if not session_model:
        lines.append("")
        lines.append(
            "  Session model undetected — alias-following agents (orchestrator, "
            "renderer, abuse-verifier) run on whatever model this session uses."
        )
    return "\n".join(lines) + "\n"


def render_orchestrator_recommendation(cfg: dict, session_model: str) -> str:
    """Human-readable pre-flight justification for the orchestrator/session model.

    Advisory: states the repo-size-derived recommendation, compares it to the
    detected session model, and — on divergence — gives the restart command (a
    running loop cannot switch its own model). The recommendation is NEVER
    binding; the user may keep the current model. Empty string when there is no
    recommendation in cfg (should not happen after resolve())."""
    rec = cfg.get("orchestrator_recommended_model")
    if not rec:
        return ""
    reason = cfg.get("orchestrator_recommendation_reason", "")
    lines = ["Orchestrator (session model) — advisory", f"  Recommended : {rec}"]
    if reason:
        width = _summary_width()
        prefix = "  Rationale   : "
        chunks = wrap(
            reason,
            width=max(20, width - len(prefix)),
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        lines.append(prefix + chunks[0])
        lines.extend(" " * len(prefix) + c for c in chunks[1:])
    if not session_model:
        lines.append("  This session: undetected — recommendation is advisory only.")
    elif _same_model(session_model, rec):
        lines.append(f"  This session: {session_model}  (✓ matches — nothing to change)")
    else:
        lines.append(f"  This session: {session_model}  (⚠ differs from the recommendation)")
        lines.append(
            f"  To scan on {rec}: /clear then /model {rec} (in-session — keeps the plugin "
            f"loaded, no relaunch flags needed), then re-run. Fresh terminal: `claude "
            f"--model {rec}` PLUS the launch flags you started this session with (e.g. "
            f"--plugin-dir). Keeping the current model is fine too — only a recommendation."
        )
    return "\n".join(lines) + "\n"


def _full_over_existing_reason(
    cfg: dict,
    pre_check: dict | None,
    compat_label: str | None,
) -> str:
    """Explain why a FULL scan is running while a complete model already exists.

    Surfaced on the run-plan Reason line so a full re-assessment over an
    existing threat model is never unexplained. Trigger precedence:
      0. assessment depth increased vs the baseline (cfg["depth_upgrade_reason"]).
      1. analysis_version incompatible  → full rebuild is mandatory.
      2. analysis schema older-compatible → full refresh re-applies new
         categories to every finding.
      3. plugin minor/major drift        → full refresh re-applies updated
         analysis to all components.
      4. explicit mode-upgrade reason (cfg["mode_upgraded_reason"], set when
         the auto-incremental → full prompt switched the mode).
      5. otherwise an explicit --full / --dry-run request.
    The prior model's version/date is appended when available so the user
    knows exactly which report is being replaced.
    """
    tier = ((pre_check or {}).get("plugin_version", {}) or {}).get("tier", "equal")
    if cfg.get("depth_upgrade_reason"):
        # Highest precedence: the user explicitly asked for a deeper assessment
        # depth than the baseline was built at. This is the trigger that flipped
        # the auto-incremental mode to full (resolve_incremental_mode), so name
        # it first.
        base = str(cfg["depth_upgrade_reason"])
    elif compat_label == "incompatible":
        base = ("existing model present, but its analysis_version is "
                "incompatible with this plugin — full rebuild required")
    elif compat_label == "older-compatible":
        base = ("existing model present; analysis schema drifted (older but "
                "compatible) — full refresh applies new categories to all findings")
    elif tier in ("minor", "major"):
        base = (f"existing model present; plugin upgraded ({tier}) — full "
                f"refresh re-applies updated analysis to all components")
    elif cfg.get("mode_upgraded_reason"):
        base = str(cfg["mode_upgraded_reason"])
    else:
        base = ("existing model present; --full requested — complete "
                "re-assessment (changelog history preserved)")
    prior = cfg.get("baseline_prior_label")
    return f"{base} [replaces {prior}]" if prior else base


def _run_plan_verdict(
    cfg: dict,
    pre_check: dict | None,
    dirty_set: dict | None,
    compat_label: str | None,
) -> dict:
    """Compute verdict + mode line + pipeline + reason for the run-plan box.

    Returns a dict with: ``verdict``, ``mode_line``, ``pipeline``, ``reason``,
    ``will_run`` (bool — True iff Stage 1 will dispatch).
    """
    mode = cfg.get("mode")
    incremental = cfg.get("incremental")

    if mode == "rebuild":
        return {
            "verdict":   "REBUILD — wipe + full re-assessment",
            "mode_line": cfg.get("mode_label", "rebuild"),
            "pipeline":  _pipeline_string(cfg, full=True),
            "reason":    "wipes prior model + cache, no T-ID stability",
            "will_run":  True,
        }
    if not incremental:
        # full / first-run / bootstrap-from-legacy
        baseline_state = cfg.get("baseline_state")
        if baseline_state == "empty":
            reason = "no prior threat-model.yaml in output dir — first full assessment"
        elif baseline_state == "legacy":
            reason = "legacy threat-model.md without yaml — bootstrap full run"
        else:
            # A complete prior model exists, yet we are running a FULL scan over
            # it. Name the trigger explicitly so the user understands WHY the
            # incremental fast-path was not taken (the #1 "why is it re-scanning
            # an existing model?" question).
            reason = _full_over_existing_reason(cfg, pre_check, compat_label)
        return {
            "verdict":   "RUN — full assessment (existing model)"
                         if baseline_state not in ("empty", "legacy")
                         else "RUN — full assessment",
            "mode_line": cfg.get("mode_label", "full"),
            "pipeline":  _pipeline_string(cfg, full=True),
            "reason":    reason,
            "will_run":  True,
        }

    # Incremental — refine via pre-check + dirty-set.
    cc_status = (pre_check or {}).get("status")
    ds_decision = (dirty_set or {}).get("decision") if dirty_set else None
    plugin_tier = ((pre_check or {}).get("plugin_version", {}) or {}).get("tier", "equal")

    if cc_status == "unchanged":
        return {
            "verdict":   "NO-OP — no source changes; pipeline skipped",
            "mode_line": "incremental — fast-abort",
            "pipeline":  "SKIPPED (no agents will run)",
            "reason":    "no committed or working-tree changes since baseline",
            "will_run":  False,
        }
    if cc_status == "noise_only":
        n = len((pre_check or {}).get("noise_only_changes", []) or [])
        return {
            "verdict":   "NOISE-ONLY — pipeline skipped",
            "mode_line": "incremental — fast-abort",
            "pipeline":  "SKIPPED (no agents will run)",
            "reason":    f"{n} non-security file(s); no security-relevant change",
            "will_run":  False,
        }
    if cc_status == "unchanged_plugin_drift":
        ver = (pre_check or {}).get("plugin_version", {}) or {}
        return {
            "verdict":   f"PLUGIN-DRIFT — plugin upgraded ({ver.get('baseline','?')} → {ver.get('current','?')}, tier={plugin_tier})",
            "mode_line": "incremental (auto)",
            "pipeline":  "PROMPT (interactive) / ABORT (CI)",
            "reason":    ver.get("message") or "plugin upgraded, source unchanged",
            "will_run":  False,
        }
    if cc_status == "changed":
        if ds_decision in ("noop_global_only", "noop_empty_input"):
            return {
                "verdict":   "NO-OP — relevant changes touch no component",
                "mode_line": "incremental — fast-abort (global manifest only)",
                "pipeline":  "SKIPPED (no agents will run)",
                "reason":    "all relevant files are top-level globals — no component glob matches",
                "will_run":  False,
            }
        if ds_decision == "ambiguous_potential_new_component":
            return {
                "verdict":   "AMBIGUOUS — possible new component",
                "mode_line": "incremental (auto, conservative)",
                "pipeline":  _pipeline_string(cfg, full=False),
                "reason":    "relevant files unmapped; Phase 2 will decide",
                "will_run":  True,
            }
        if ds_decision == "dirty":
            ids = (dirty_set or {}).get("dirty_component_ids", []) or []
            scoped = _pipeline_string(cfg, full=False, dirty_components=ids)
            drift_suffix = ""
            if plugin_tier in ("minor", "major"):
                drift_suffix = f" (⚠ plugin tier={plugin_tier} — consider --full)"
            return {
                "verdict":   f"RUN — {len(ids)} component(s) dirty{drift_suffix}",
                "mode_line": f"incremental — STRIDE delta on {len(ids)} component(s)",
                "pipeline":  scoped,
                "reason":    f"changes in {', '.join(ids[:5])}",
                "will_run":  True,
            }
        # Pre-check exit 1 but dirty-set not consulted (or skipped) —
        # fall through to standard incremental conservatively.
        return {
            "verdict":   "RUN — incremental (delta scope unresolved)",
            "mode_line": "incremental (auto)",
            "pipeline":  _pipeline_string(cfg, full=False),
            "reason":    "relevant changes detected; agent will compute dirty set",
            "will_run":  True,
        }

    # Default fall-through (no pre-check ran for some reason — e.g. --dry-run
    # path that forced INCREMENTAL=false, or first-run where pre-check
    # short-circuited at no_baseline). Treat as full pipeline so the box is
    # still informative.
    return {
        "verdict":   "RUN — full pipeline (default)",
        "mode_line": cfg.get("mode_label", "full"),
        "pipeline":  _pipeline_string(cfg, full=True),
        "reason":    "no incremental pre-check signal available",
        "will_run":  True,
    }


def _pipeline_string(
    cfg: dict, *, full: bool, dirty_components: list[str] | None = None,
) -> str:
    """Return the human-readable list of stages that will execute.

    ``full=True`` uses the full pipeline (recon → architecture → STRIDE → …).
    ``full=False`` emits the incremental delta path; when ``dirty_components``
    is set, the STRIDE step is annotated with the scope.
    """
    if full:
        steps = ["recon", "architecture", "STRIDE", "triage", "render"]
    else:
        if dirty_components:
            scope = ", ".join(dirty_components[:3])
            if len(dirty_components) > 3:
                scope += f", +{len(dirty_components) - 3}"
            stride = f"STRIDE delta ({scope})"
        else:
            stride = "STRIDE delta"
        steps = ["change check", "recon", stride, "triage", "render"]
    if not cfg.get("skip_qa"):
        steps.append("QA")
    if cfg.get("architect_review"):
        steps.append("architect review")
    return " -> ".join(steps)


def _render_depth_tradeoff(cfg: dict) -> list[str]:
    """A prominent, visually-separated depth-vs-coverage callout.

    Rendered as its own marked block (above ``Notes``) rather than one bullet
    buried in the advisory list — the depth guidance kept getting lost there.
    The marker carries the intent: ``⚠`` is a WARNING at ``quick`` (shallow),
    ``ℹ`` is a neutral reference at ``standard``. Returns ``[]`` at ``thorough``
    (the deepest tier — no upsell). Body paragraphs wrap to the summary width,
    matching the ``Notes`` formatter.
    """
    depth = cfg.get("assessment_depth")
    if depth == "quick":
        header = "⚠ Depth tradeoff"
        paras = [
            "--quick is a fast triage pass — shallow coverage (QA, "
            "walkthroughs, abuse-case verification and §7 enrichment are "
            "skipped, STRIDE is depth-capped).",
            "For a dependable assessment use --standard (default) or "
            "--thorough (deepest: deeper per-component analysis + architect "
            "review, Opus). More depth = higher cost & time.",
        ]
    elif depth == "standard":
        header = "ℹ Depth tradeoff"
        paras = [
            "--standard is the balanced default. --thorough digs deeper "
            "(deeper per-component analysis + architect review, Opus "
            "reasoning) — at correspondingly higher cost & time.",
        ]
    else:
        return []

    width = _summary_width()
    indent = "  "
    value_width = max(20, width - len(indent))
    lines: list[str] = [header]
    for p in paras:
        chunks = wrap(
            p,
            width=value_width,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        lines.extend(indent + c for c in chunks)
    return lines


def _run_plan_notes(
    verdict: dict,
    cfg: dict,
    pre_check: dict | None,
    dirty_set: dict | None,
    compat_label: str | None,
) -> list[str]:
    """Notes / recommendations to surface below the box.

    Depth-vs-coverage guidance is NOT here — it is a dedicated, marked callout
    rendered above this block by :func:`_render_depth_tradeoff`.
    """
    notes: list[str] = []

    plugin_tier = ((pre_check or {}).get("plugin_version", {}) or {}).get("tier", "equal")
    if verdict["will_run"]:
        notes.append("Ctrl-C now to abort before any tokens are spent.")
        if not verdict["mode_line"].startswith("full") and not verdict["mode_line"].startswith("rebuild"):
            notes.append("Pass --full to widen the scope to a complete re-assessment.")
    else:
        notes.append("threat-model.md preserved as-is.")
        notes.append("Pass --full to force a complete re-assessment regardless.")

    if plugin_tier == "major":
        notes.append(
            "STRONGLY consider --full — major plugin bump may contain "
            "breaking analysis changes that incremental cannot retro-apply."
        )
    elif plugin_tier == "minor":
        notes.append(
            "Consider --full — minor plugin bumps usually ship analysis "
            "improvements that only affect newly-scanned code in incremental."
        )

    if compat_label == "older-compatible":
        notes.append(
            "Analysis schema drifted (baseline analysis_version older but "
            "compatible) — full rebuild applies new categories to ALL findings."
        )

    if cfg.get("repo_size_capped"):
        notes.append(
            f"Large repo ({cfg.get('repo_size_source_files')} source files) → "
            f"longer run expected; reasoning stays on the default tier and all "
            f"criteria-selected components are analyzed (no attack surface dropped)."
        )

    return notes


def _summary_width() -> int:
    """Return a conservative box width for terminal and headless output."""
    columns = shutil.get_terminal_size(fallback=(88, 20)).columns
    if columns < 64:
        return 64
    return min(88, columns)


def _box_line(text: str = "", width: int | None = None) -> str:
    width = width or _summary_width()
    inner = width - 4
    if len(text) > inner:
        text = text[:inner]
    return f"│ {text.ljust(inner)} │"


def _box_heading(title: str, width: int | None = None) -> str:
    width = width or _summary_width()
    prefix = f"╭─ {title} "
    return prefix + ("─" * max(0, width - len(prefix) - 1)) + "╮"


def _box_footer(width: int | None = None) -> str:
    width = width or _summary_width()
    return "╰" + ("─" * (width - 2)) + "╯"


def _box_section(title: str, width: int) -> list[str]:
    return [_box_line(title, width)]


def _box_kv(label: str, value: Any, width: int) -> list[str]:
    inner = width - 4
    prefix = f"  {label:<10}: "
    value_width = max(12, inner - len(prefix))
    chunks = wrap(
        str(value),
        width=value_width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    lines = [_box_line(prefix + chunks[0], width)]
    continuation = " " * len(prefix)
    lines.extend(_box_line(continuation + chunk, width) for chunk in chunks[1:])
    return lines


def _box_bullet(text: str, width: int) -> list[str]:
    """Render a bullet line without the ``label : value`` padding.

    Used inside the run-plan box for the per-file "Why this run …"
    enumeration where each line is just a free-form sentence prefixed
    with ``• ``.
    """
    inner = width - 4
    prefix = "  • "
    value_width = max(12, inner - len(prefix))
    chunks = wrap(
        str(text),
        width=value_width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    lines = [_box_line(prefix + chunks[0], width)]
    continuation = " " * len(prefix)
    lines.extend(_box_line(continuation + chunk, width) for chunk in chunks[1:])
    return lines


def _render_summary_box(cfg: dict) -> list[str]:
    width = _summary_width()
    lines = [_box_heading("Create Threat Model", width)]

    lines.extend(_box_section("Target", width))
    lines.extend(_box_kv("Repository", cfg["repo_root"], width))
    lines.extend(_box_kv("Scope", _format_target_scope(cfg), width))
    lines.extend(_box_kv("Output", cfg["output_dir"], width))

    lines.append(_box_line(width=width))
    lines.extend(_box_section("Run Plan", width))
    lines.extend(
        _box_kv(
            "Plugin",
            f"appsec-advisor {cfg['plugin_version']} "
            f"(analysis v{cfg['analysis_version']})",
            width,
        )
    )
    lines.extend(_box_kv("Mode", cfg["mode_label"], width))
    lines.extend(_box_kv("Depth", _format_depth_summary(cfg), width))
    lines.extend(_box_kv("Pipeline", _format_pipeline_summary(cfg), width))
    lines.extend(_box_kv("Reasoning", _format_reasoning_summary(cfg), width))
    lines.extend(_box_kv("STRIDE cap", _format_stride_cap(cfg), width))

    active_options = _summary_active_options(cfg)
    if active_options:
        lines.append(_box_line(width=width))
        lines.extend(_box_section("Active Options", width))
        for label, value in active_options:
            lines.extend(_box_kv(label, value, width))

    lines.append(_box_footer(width))
    return lines


def _format_target_scope(cfg: dict) -> str:
    scope = " ".join(cfg.get("scope") or []).strip()
    if cfg.get("incremental"):
        if scope:
            return f"incremental delta; user focus: {scope}"
        return "incremental delta from previous threat-model.yaml"
    if scope:
        return scope
    return "full repository"


def _format_depth_summary(cfg: dict) -> str:
    """Render the depth row.

    The component-count line is suppressed for incremental runs because it is
    meaningless there: the dirty-set defines the scope. For full runs the
    analyzed set is criteria-selected (not a fixed number), so the row names
    the mechanism rather than a misleading count; the Files block already shows
    the actual ``N known, M dirty`` counts.
    """
    parts: list[str] = [cfg.get("assessment_depth", "standard")]
    if not cfg.get("incremental"):
        parts.append("criteria-selected components")
    parts.append(
        f"STRIDE turns {cfg.get('stride_turns_simple', '?')}/"
        f"{cfg.get('stride_turns_moderate', '?')}/"
        f"{cfg.get('stride_turns_complex', '?')}"
    )
    parts.append(f"diagrams {cfg.get('diagram_depth', '?')}")
    parts.append(f"QA {cfg.get('qa_depth', '?')}")
    return "; ".join(parts)


def _format_pipeline_summary(cfg: dict) -> str:
    if cfg.get("incremental"):
        steps = ["change check", "recon", "STRIDE delta", "triage", "render"]
    else:
        steps = ["recon", "architecture", "STRIDE", "triage", "render"]
    if not cfg.get("skip_qa"):
        steps.append("QA")
    if cfg.get("architect_review"):
        steps.append("architect review")
    return " -> ".join(steps)


def _format_reasoning_summary(cfg: dict) -> str:
    mode = canonical_reasoning_model(cfg.get("reasoning_model")) or "unknown"
    if cfg.get("opus_disabled"):
        return f"{mode}; no-opus ceiling → all Opus selections downgraded to Sonnet"

    def short(model: str | None) -> str:
        # Keep the concrete version — with the standard buy-back the tier mixes
        # Sonnet 4.6 and Sonnet 5, so a bare "Sonnet" would be ambiguous.
        raw = (model or "unknown").replace("claude-", "")
        return (
            raw.replace("sonnet-4-6", "Sonnet 4.6")
            .replace("sonnet-5", "Sonnet 5")
            .replace("opus-4-8", "Opus 4.8")
            .replace("opus-4-7", "Opus")
            .replace("haiku-4-5", "Haiku")
        )

    stride = short(cfg.get("stride_model"))
    triage = short(cfg.get("triage_model"))
    merge = short(cfg.get("merger_model"))
    # sonnet-economy routes the deterministic-leaning periphery to Haiku.
    prefix = "cheap phases Haiku; " if mode == "sonnet-economy" else ""
    if stride == triage == merge:
        return f"{mode}; {prefix}STRIDE/triage/merge {stride}"
    return f"{mode}; {prefix}STRIDE {stride}; triage {triage}; merge {merge}"


def _format_stride_cap(cfg: dict) -> str:
    """Always-on pre-flight row: how many threats STRIDE keeps per category.

    Sourced from the resolved ``stride_profile.max_threats_per_category`` — set
    either by ``--stride-cap N`` at any depth, or implicitly by the quick
    triage profile (cap 1). When absent, standard/thorough keep full STRIDE
    depth. Shown in both states so the user always sees, before any tokens are
    spent, whether the per-component threat count is bounded.
    """
    cap = (cfg.get("stride_profile") or {}).get("max_threats_per_category")
    if cap:
        return f"≤{cap} per STRIDE category per component (Criticals always kept)"
    return "none — full STRIDE depth (all threats kept)"


def _summary_active_options(cfg: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []

    org_summary = _format_org_profile_summary(cfg)
    if org_summary:
        rows.append(("Org profile", org_summary))

    outputs = _format_outputs_summary(cfg)
    if outputs:
        rows.append(("Outputs", outputs))

    extras: list[str] = []
    if cfg.get("check_requirements"):
        extras.append(f"requirements ({cfg['requirements_label']})")
    if cfg.get("architect_review"):
        extras.append(f"architect review ({cfg['architect_label']})")
    # Abuse-case verification (Stage 1c) forced ON where it would otherwise be
    # off — i.e. explicit --abuse-cases at quick depth. The default-on
    # standard/thorough case is silent (not a deviation).
    if cfg.get("abuse_case_label") == "enabled (--abuse-cases)":
        extras.append("abuse-case verification (--abuse-cases)")
    if extras:
        rows.append(("Extras", ", ".join(extras)))

    skips: list[str] = []
    if cfg.get("skip_qa"):
        skips.append(f"QA {cfg.get('skip_qa_label', 'skipped')}")
    if cfg.get("skip_attack_walkthroughs"):
        skips.append(
            "walkthroughs "
            f"{cfg.get('skip_attack_walkthroughs_label', 'skipped')}"
        )
    # Stage 1c abuse-case verifier fan-out (matcher + verifiers + chain fold) is
    # the most expensive part of Stage 1c — surface whenever it is skipped
    # (explicit --no-abuse-cases, or the auto quick-depth default), mirroring how
    # QA / walkthroughs surface their skip.
    if cfg.get("skip_abuse_case_verification"):
        skips.append(
            "abuse-case verification "
            f"{cfg.get('abuse_case_label', 'skipped')}"
        )
    if skips:
        rows.append(("Skips", ", ".join(skips)))

    flags = _format_run_flags(cfg)
    if flags:
        rows.append(("Run flags", flags))

    # Depth-reduced STRIDE profiles (quick) still surface their label here.
    # The per-category cap is NOT shown via this row — it has its own always-on
    # "STRIDE cap" line in the Configuration block, so a "full (per-category
    # cap N)" label would only duplicate it.
    sp_label = (cfg.get("stride_profile") or {}).get(
        "stride_profile_label", "full"
    )
    if not sp_label.startswith("full"):
        rows.append(("STRIDE", sp_label))

    # Full-M1 parallel-STRIDE opt-in surfacing. Mirror the exact skill-Bash
    # resolution (SKILL-impl.md "Configuration Resolution"): env-gated, only
    # honoured for from-scratch runs (full/rebuild). Surface the requested-but-
    # inactive case too, so a user who set the env var on an incremental run
    # sees why no per-component fan-out happened.
    # Parallel STRIDE is DEFAULT-ON for full/rebuild; opt-OUT via
    # APPSEC_PARALLEL_STRIDE=0 (mirror the skill resolution at SKILL-impl.md
    # "Configuration Resolution"). Incremental/rerender never parallelise.
    _ps_optout = os.environ.get("APPSEC_PARALLEL_STRIDE") == "0"
    parallel_active = cfg.get("mode") in ("full", "rebuild") and not _ps_optout
    if cfg.get("mode") in ("full", "rebuild"):
        if parallel_active:
            rows.append((
                "STRIDE disp",
                f"bounded waves (up to {cfg.get('stride_concurrency', STRIDE_DISPATCH_CONCURRENCY)} concurrent; Level-0)",
            ))
        else:
            rows.append((
                "STRIDE disp",
                "serial inline (disabled via APPSEC_PARALLEL_STRIDE=0)",
            ))

    # Live-phase console surfacing (opt-in, experimental). Mirror the skill-Bash
    # resolution: honoured only when PARALLEL_STRIDE is NOT active (that path has
    # its own per-component rows). Surface the inactive case so a user who set the
    # env var alongside parallel-stride sees why no background dispatch happened.
    if os.environ.get("APPSEC_LIVE_PHASE") == "1":
        if not parallel_active:
            rows.append(("Live phase", "on (background dispatch + console phase)"))
        else:
            rows.append((
                "Live phase",
                "requested — inactive (PARALLEL_STRIDE wins)",
            ))

    # M11/M9 — wall-time + cost deadline display (existing behaviour).
    deadline_parts = []
    if cfg.get("max_wall_time_seconds"):
        sec = cfg["max_wall_time_seconds"]
        if sec >= 3600:
            h = sec // 3600
            m = (sec % 3600) // 60
            deadline_parts.append(
                f"wall-time {h} h" + (f" {m} min" if m else "")
            )
        else:
            deadline_parts.append(f"wall-time {sec // 60} min")
    if cfg.get("max_cost_usd"):
        deadline_parts.append(f"cost ${cfg['max_cost_usd']:.2f}")
    if deadline_parts:
        rows.append(("Limits", " / ".join(deadline_parts)))

    return rows


def _format_org_profile_summary(cfg: dict) -> str:
    org = cfg.get("org_profile") or {}
    if not org.get("active"):
        return ""
    preset = cfg.get("preset") or {}
    name = org.get("name") or org.get("id") or "active"
    org_id = org.get("id")
    if org_id and org_id != name:
        name = f"{name} ({org_id})"
    parts = [name]
    preset_name = preset.get("name")
    if preset_name:
        parts.append(f"preset {preset_name}")
    source = org.get("source")
    if source:
        parts.append(f"source {source}")
    return ", ".join(parts)


def _format_outputs_summary(cfg: dict) -> str:
    outputs = ["markdown"]
    if cfg.get("write_yaml"):
        outputs.append("yaml")
    else:
        outputs.append("no yaml")
    if cfg.get("write_sarif"):
        outputs.append("sarif")
    if cfg.get("write_pentest_tasks"):
        fmt = cfg.get("pentest_format") or "generic"
        target = cfg.get("pentest_target")
        if target:
            outputs.append(f"pentest-tasks ({fmt}, target: {target})")
        else:
            outputs.append(f"pentest-tasks ({fmt})")
    if outputs == ["markdown", "yaml"]:
        return ""
    return " + ".join(outputs)


def _configuration_post_summary_notes(cfg: dict) -> list[str]:
    post_lines: list[str] = []

    # --- Post-summary notes (preserved) -----------------------------------
    if cfg.get("output_outside_repo"):
        post_lines.append(
            "Note: output directory is outside the repository — "
            ".gitignore entries will be skipped."
        )
    if cfg.get("post_summary_note"):
        post_lines.append(cfg["post_summary_note"])
    if cfg.get("mode") == "incremental":
        post_lines.append(
            f"Recommendation: Run with --full periodically to ensure "
            f"complete coverage with plugin v{cfg['plugin_version']}."
        )
    if not cfg.get("check_requirements") \
            and cfg["requirements_label"].startswith("disabled (config)"):
        post_lines.append(
            "Tip: requirements compliance is disabled. Pass --requirements "
            "or set requirements_yaml_url in "
            "skills/audit-security-requirements/config.json to enable."
        )
    if cfg.get("repo_size_capped"):
        post_lines.append(
            f"Note: large repository ({cfg['repo_size_source_files']} source files) "
            f"→ longer run expected. Reasoning stays on the default tier and all "
            f"criteria-selected components are still analyzed (no attack surface "
            f"dropped). Pass --assessment-depth thorough to also analyze internal-only "
            f"components and deepen per-component budget."
        )

    # Mermaid validator status — surfaces whether Layer B (authoritative
    # Mermaid grammar parsing via Node + jsdom) is available. When jsdom
    # is missing the validator silently falls back to Layer A regex-only,
    # which catches some bug classes but not grammar-level breakages
    # (empty `linkStyle`, multi-class chaining, etc.). Surfacing this as
    # a Configuration Summary hint lets the user decide whether to install
    # jsdom before trusting the run's Mermaid output.
    try:
        import os as _os
        plugin_root = _os.environ.get("CLAUDE_PLUGIN_ROOT") or ""
        if plugin_root:
            scripts_dir = Path(plugin_root) / "scripts"
            jsdom_local = scripts_dir / "node_modules" / "jsdom" / "package.json"
            jsdom_global = Path("/usr/lib/node_modules/jsdom/package.json")
            if not (jsdom_local.is_file() or jsdom_global.is_file()):
                post_lines.append(
                    "Note: Mermaid validator running in Layer A (regex) only — "
                    "install jsdom for grammar-level checks: "
                    f"npm install --prefix {scripts_dir} jsdom"
                )
    except Exception:
        pass

    return post_lines


def _format_outputs(cfg: dict) -> str:
    """Outputs row content. Empty string when nothing deviates from md+yaml.

    Renders only the deltas: ``-yaml`` when the user passed ``--no-yaml``,
    ``+ sarif`` for ``--sarif``, ``+ pentest-tasks (<format>[, target: <url>])``
    for ``--pentest-tasks``. ``--pdf`` is a skill-layer flag and not part
    of the resolved cfg.
    """
    parts = []
    if not cfg.get("write_yaml"):
        parts.append("-yaml (--no-yaml)")
    if cfg.get("write_sarif"):
        parts.append("+ sarif")
    if cfg.get("write_pentest_tasks"):
        fmt = cfg.get("pentest_format") or "generic"
        target = cfg.get("pentest_target")
        if target:
            parts.append(f"+ pentest-tasks ({fmt}, target: {target})")
        else:
            parts.append(f"+ pentest-tasks ({fmt})")
    return ", ".join(parts)


def _format_run_flags(cfg: dict) -> str:
    """Comma-joined list of run-flags that DEVIATE from the silent default.

    Tracing is on by default since M3.6 — surfacing it in every summary
    would defeat the "show only deviations" rule that this row exists for.
    The opt-out (``--no-tracing``) is the deviation worth flagging.
    """
    flags = []
    if cfg.get("dry_run"):            flags.append("dry-run")
    if cfg.get("verbose"):            flags.append("verbose")
    if cfg.get("quiet"):              flags.append("quiet")
    if not cfg.get("tracing"):        flags.append("no-tracing")
    if cfg.get("scan_manifest"):      flags.append("scan-manifest")
    if cfg.get("keep_runtime_files"): flags.append("keep-runtime-files")
    if cfg.get("pr_mode"):             flags.append("pr-mode")
    if cfg.get("qa_scan_repo"):        flags.append("qa-scan-repo")
    return ", ".join(flags)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    plugin_root = Path(__file__).resolve().parent.parent

    # Separate ``--emit-file`` / ``--config-summary`` / ``--validate-only``
    # meta flags from the user argv before it reaches the resolver's
    # argparser, so that scope-word parsing isn't polluted by them.
    # ``--validate-only`` runs argparse + conflict detection only and exits 0
    # without producing JSON output, used by the skill at preflight time to
    # fail-fast on unknown/invalid flags before any state-cleanup runs.
    # ``--force`` is a skill-layer flag (rebuild guard) and is stripped here
    # too so validate-only doesn't reject otherwise-valid invocations.
    emit_file_flag     = "--emit-file" in argv
    config_summary     = "--config-summary" in argv
    validate_only      = "--validate-only" in argv

    # ``--run-plan`` renders the consolidated post-pre-check box. Its
    # companion flags carry the JSON payloads the renderer needs:
    #   --pre-check-file <path>   FAST_PATH_OUTPUT JSON (or "-" for stdin)
    #   --dirty-set-file <path>   DIRTY_SET_OUTPUT JSON (or "-" for stdin)
    #   --compat-label <label>    "equal" / "older-compatible" / …
    # The cfg itself is loaded from ``$OUTPUT_DIR/.skill-config.json`` —
    # the same file ``--emit-file`` writes — so this never re-resolves
    # user argv after the skill has already fixed those values.
    run_plan_flag = "--run-plan" in argv
    run_plan_notes_flag = "--run-plan-notes" in argv
    any_run_plan = run_plan_flag or run_plan_notes_flag

    # ``--effective-routing`` renders the per-agent routing table. Its companion
    # ``--session-model <id>`` carries the detected host session model (from
    # scripts/detect_session_model.py) so the ``sonnet`` alias resolves to a
    # concrete version, and is ALSO folded into the --run-plan box (cost callout).
    routing_flag = "--effective-routing" in argv
    # ``--orchestrator-recommendation`` renders the advisory session-model
    # justification block (repo-size → recommended model + restart hint). Uses the
    # same ``--session-model <id>`` companion as --effective-routing.
    orch_rec_flag = "--orchestrator-recommendation" in argv
    session_model_arg = ""
    for i, a in enumerate(argv):
        if a == "--session-model" and i + 1 < len(argv):
            session_model_arg = argv[i + 1]
            break
    pre_check_path: str | None = None
    dirty_set_path: str | None = None
    compat_label: str | None = None
    if any_run_plan:
        i = 0
        while i < len(argv):
            a = argv[i]
            if a == "--pre-check-file" and i + 1 < len(argv):
                pre_check_path = argv[i + 1]
                i += 2
                continue
            if a == "--dirty-set-file" and i + 1 < len(argv):
                dirty_set_path = argv[i + 1]
                i += 2
                continue
            if a == "--compat-label" and i + 1 < len(argv):
                compat_label = argv[i + 1]
                i += 2
                continue
            i += 1

    filtered = [a for a in argv if a not in (
        "--emit-file", "--config-summary", "--validate-only", "--force",
        "--run-plan", "--run-plan-notes", "--effective-routing",
        "--orchestrator-recommendation",
    )]
    # Strip the --session-model companion flag + its value (used by both
    # --effective-routing and --run-plan) so resolve() doesn't choke on it.
    if "--session-model" in filtered:
        clean_r: list[str] = []
        skip_next_r = False
        for a in filtered:
            if skip_next_r:
                skip_next_r = False
                continue
            if a == "--session-model":
                skip_next_r = True
                continue
            clean_r.append(a)
        filtered = clean_r
    # Strip the run-plan companion flags + their values too.
    if any_run_plan:
        clean: list[str] = []
        skip_next = False
        for a in filtered:
            if skip_next:
                skip_next = False
                continue
            if a in ("--pre-check-file", "--dirty-set-file", "--compat-label"):
                skip_next = True
                continue
            clean.append(a)
        filtered = clean

    if routing_flag:
        # Load the already-resolved cfg (same pattern as --run-plan), then
        # render the effective routing table with the injected session model.
        try:
            cfg_candidate = resolve(filtered, plugin_root)
            sc_path = Path(cfg_candidate["output_dir"]) / ".skill-config.json"
            if sc_path.is_file():
                cfg = json.loads(sc_path.read_text(encoding="utf-8"))
            else:
                cfg = cfg_candidate
        except SystemExit:
            raise
        except Exception:
            cfg = resolve(filtered, plugin_root)
        print(render_effective_routing(cfg, session_model_arg), end="")
        return 0

    if orch_rec_flag:
        # Same cfg-load pattern as --effective-routing: prefer the persisted
        # .skill-config.json, fall back to a fresh resolve.
        try:
            cfg_candidate = resolve(filtered, plugin_root)
            sc_path = Path(cfg_candidate["output_dir"]) / ".skill-config.json"
            if sc_path.is_file():
                cfg = json.loads(sc_path.read_text(encoding="utf-8"))
            else:
                cfg = cfg_candidate
        except SystemExit:
            raise
        except Exception:
            cfg = resolve(filtered, plugin_root)
        print(render_orchestrator_recommendation(cfg, session_model_arg), end="")
        return 0

    if any_run_plan:
        # The skill has already resolved the cfg and persisted it to
        # ``.skill-config.json``. Read from there so the renderer sees the
        # exact same values downstream consumers do — no second resolve.
        # When the file is missing fall back to a fresh resolve so this
        # subcommand still works when called manually.
        cfg = None
        # Try to find OUTPUT_DIR via the user's argv (scope words may
        # also include --output, etc.); resolve() handles that.
        try:
            cfg_candidate = resolve(filtered, plugin_root)
            sc_path = Path(cfg_candidate["output_dir"]) / ".skill-config.json"
            if sc_path.is_file():
                cfg = json.loads(sc_path.read_text(encoding="utf-8"))
            else:
                cfg = cfg_candidate
        except SystemExit:
            raise
        except Exception:
            cfg = resolve(filtered, plugin_root)

        def _read_json(p: str | None) -> dict | None:
            if not p:
                return None
            try:
                if p == "-":
                    txt = sys.stdin.read()
                else:
                    txt = Path(p).read_text(encoding="utf-8")
                return json.loads(txt) if txt.strip() else None
            except Exception:
                return None

        pre_check = _read_json(pre_check_path)
        dirty_set = _read_json(dirty_set_path)
        if run_plan_notes_flag:
            print(
                render_run_plan_notes(cfg, pre_check, dirty_set, compat_label, session_model_arg),
                end="",
            )
        else:
            print(render_run_plan(cfg, pre_check, dirty_set, compat_label, session_model_arg), end="")
        return 0

    cfg = resolve(filtered, plugin_root)

    if validate_only:
        # argparse already exits non-zero on unknown args; reaching here
        # means parsing succeeded. resolve() also raises on conflict pairs.
        return 0

    if config_summary:
        print(render_configuration_summary(cfg), end="")
        return 0

    # Emit JSON on stdout.
    js = json.dumps(cfg, indent=2, sort_keys=True) + "\n"
    print(js, end="")

    # Side-effect: persist to .skill-config.json for downstream scripts.
    if emit_file_flag:
        try:
            (Path(cfg["output_dir"]) / ".skill-config.json").write_text(
                js, encoding="utf-8"
            )
        except OSError:
            pass  # non-fatal; JSON is on stdout regardless
        # Also persist the org-profile slice on its own — the status skill,
        # the security-coach hook, and check_skill_enabled.py all read
        # this file directly.
        try:
            org_payload = {
                "org_profile": cfg.get("org_profile") or {},
                "preset": cfg.get("preset"),
                "defaults": cfg.get("org_profile_defaults") or {},
                "requirements_source": cfg.get("org_profile_requirements_source"),
                "llm_context_documents": cfg.get("org_profile_context_documents") or [],
                "skill_toggles": cfg.get("org_profile_skill_toggles") or {},
                "security_coach": cfg.get("org_profile_security_coach"),
            }
            (Path(cfg["output_dir"]) / ".org-profile-effective.json").write_text(
                json.dumps(org_payload, indent=2) + "\n", encoding="utf-8"
            )
        except OSError:
            pass  # non-fatal

        # Note: the human-readable Configuration Summary box is intentionally
        # NOT emitted here. The consolidated run-plan box (--run-plan) is
        # the canonical user-visible surface and lands AFTER the pre-check
        # so the user sees the actual pipeline parametrisation, not the raw
        # user argv resolution.

    return 0


if __name__ == "__main__":
    sys.exit(main())
