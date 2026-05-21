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
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import wrap
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Model matrix — mirrors SKILL.md "Reasoning Model Resolution → Mode matrix"
# ---------------------------------------------------------------------------


MODEL_MATRIX = {
    "sonnet": {
        "stride": "claude-sonnet-4-6",
        "triage": "claude-sonnet-4-6",
        "merger": "claude-sonnet-4-6",
    },
    "opus-cheap": {
        "stride": "claude-sonnet-4-6",
        # triage stays on Sonnet: scripts/triage_validate_ratings.py provides a
        # deterministic floor (outlier thresholds, completeness counts, CVSS
        # eligibility); the agent only does judgment-call validation on top.
        # Opus here was overkill — Sonnet handles the structured input.
        "triage": "claude-sonnet-4-6",
        "merger": "claude-opus-4-7",
    },
    "opus": {
        "stride": "claude-opus-4-7",
        "triage": "claude-opus-4-7",
        "merger": "claude-opus-4-7",
    },
    # haiku-economy: STRIDE/triage/merger bleiben wie bei sonnet — der
    # Hauptwertbeitrag (Threat-Reasoning) wird NICHT auf Haiku geroutet.
    # Der Haiku-Hebel greift bei den deterministisch-näheren Agenten via
    # EXTENDED_MODEL_MATRIX (context-resolver, recon-scanner, qa-routine,
    # config-scanner). Quick-Mode bekommt zusätzlich eine STRIDE-Tiefe-
    # Reduktion via resolve_stride_profile().
    "haiku-economy": {
        "stride": "claude-sonnet-4-6",
        "triage": "claude-sonnet-4-6",
        "merger": "claude-sonnet-4-6",
    },
}

# Routing für Agenten jenseits von stride/triage/merger.
# Schlüssel: (reasoning_tier, depth) → agent_type → model.
# Default-Routing greift für sonnet/opus-cheap/opus (= unverändert zu heute).
# haiku-economy hat depth-spezifisches Routing.
HAIKU = "claude-haiku-4-5"
SONNET = "claude-sonnet-4-6"

EXTENDED_MODEL_MATRIX: dict[tuple[str, str], dict[str, str]] = {
    # haiku-economy: extended-agent routing.
    #
    # context-resolver, recon-scanner, config-scanner are deterministic
    # tasks (extraction / grep / rule-engine application against a YAML
    # check catalog) — they run on Haiku at every depth.
    # qa_routine moves up to Sonnet at thorough because the document is
    # bigger and more cross-references need reconciling.
    ("haiku-economy", "quick"): {
        "context_resolver": HAIKU,
        "recon_scanner":    HAIKU,
        "qa_routine":       HAIKU,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
    },
    ("haiku-economy", "standard"): {
        "context_resolver": HAIKU,
        "recon_scanner":    HAIKU,
        "qa_routine":       HAIKU,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
    },
    ("haiku-economy", "thorough"): {
        "context_resolver": HAIKU,
        "recon_scanner":    HAIKU,
        "qa_routine":       SONNET,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
    },
}

# Default-Routing für sonnet/opus-cheap/opus.
# Auch bei den Default-Tiers werden context-resolver, recon-scanner und
# config-scanner auf Haiku geroutet — diese Phasen sind reine Extraktion /
# Grep / Lookup-Tabellen-Anwendung und brauchen keinen Sonnet-Floor.
# Wer das überschreiben möchte, setzt APPSEC_RECON_SCANNER_MODEL etc.
_DEFAULT_EXTENDED_ROUTING = {
    "context_resolver": HAIKU,
    "recon_scanner":    HAIKU,
    "qa_routine":       SONNET,
    "qa_content":       SONNET,
    "config_scanner":   HAIKU,
    "orchestrator":     SONNET,
}

# Quick-Mode STRIDE-Tiefe-Reduktion. Modell bleibt Sonnet — reduziert
# wird nur der Aufgabenumfang. Greift unabhängig von der Reasoning-Tier
# wenn assessment_depth == "quick".
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
    "max_threats_per_category": 2,     # B
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

DEPTH_PARAMS = {
    "quick":    {"components": 3, "simple": 10, "moderate": 15, "complex": 20,
                 "diagrams": "minimal",  "qa": "core", "qa_label": "skipped"},
    "standard": {"components": 5, "simple": 15, "moderate": 22, "complex": 31,
                 "diagrams": "standard", "qa": "full", "qa_label": "full"},
    "thorough": {"components": 8, "simple": 20, "moderate": 28, "complex": 35,
                 "diagrams": "extended", "qa": "extended", "qa_label": "extended"},
}


# ---------------------------------------------------------------------------
# Conflict detection — runs before any resolution
# ---------------------------------------------------------------------------


CONFLICT_PAIRS: list[tuple[str, str, str]] = [
    # (attr_a, attr_b, error_message)
    ("yaml",         "no_yaml",         "--yaml and --no-yaml cannot be used together."),
    ("requirements", "no_requirements", "--requirements and --no-requirements cannot be used together."),
    ("full",         "incremental",     "--full and --incremental cannot be used together."),
    ("rebuild",      "incremental",     "--rebuild discards all prior state; --incremental requires it. Pick one."),
    ("rebuild",      "resume",          "--rebuild wipes the checkpoint file; --resume needs it. Pick one."),
    ("architect_review", "no_architect_review", "--architect-review and --no-architect-review cannot be used together."),
    ("quick",        "thorough",        "--quick and --thorough cannot be used together."),
    ("enrich_arch",  "no_enrich_arch",  "--enrich-arch and --no-enrich-arch cannot be used together."),
    ("schema_v1",    "schema_v2",       "--schema-v1 and --schema-v2 cannot be used together."),
]


def detect_conflicts(ns: argparse.Namespace) -> Optional[str]:
    for a, b, msg in CONFLICT_PAIRS:
        if getattr(ns, a, False) and getattr(ns, b, False):
            return msg
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
    label = (f"{depth} (components: {params['components']}, STRIDE turns: "
             f"{params['simple']}/{params['moderate']}/{params['complex']}, "
             f"diagrams: {params['diagrams']}, QA: {params['qa_label']})")
    return {
        "assessment_depth":      depth,
        "max_stride_components": params["components"],
        "stride_turns_simple":   params["simple"],
        "stride_turns_moderate": params["moderate"],
        "stride_turns_complex":  params["complex"],
        "diagram_depth":         params["diagrams"],
        "qa_depth":              params["qa"],
        "depth_label":           label,
    }


# B2c — repo-size auto-cap thresholds.
# Source: 2026-04-27 juice-shop incident — Juice Shop has ~430 TS/JS files,
# 5 STRIDE components consumed 50+ minutes in Phase 9 with cold caches and
# never finished. With 3 components, the same depth-standard run is
# expected to fit in ~12-18 min Phase 9.
LARGE_REPO_SOURCE_FILE_THRESHOLD = 400
LARGE_REPO_CAP_COMPONENTS = 3
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
    """B2c — auto-cap MAX_STRIDE_COMPONENTS on large repos.

    Triggers only when:
      * assessment_depth is "standard" (the default tier — so the user did
        not explicitly opt for a deeper analysis)
      * source-file count > LARGE_REPO_SOURCE_FILE_THRESHOLD
      * the user did not pass --assessment-depth thorough explicitly

    On trigger: cap MAX_STRIDE_COMPONENTS at LARGE_REPO_CAP_COMPONENTS (3),
    and append a (capped) marker to depth_label so the user sees the cap
    in the configuration summary.

    Returns the patched cfg slice (dict — not the full cfg) so the caller
    can `cfg.update(...)` it.
    """
    if cfg.get("assessment_depth") != "standard":
        return {}
    src_count = _count_source_files(repo_root)
    if src_count <= LARGE_REPO_SOURCE_FILE_THRESHOLD:
        return {}
    # Cap the components and patch the label.
    new_components = LARGE_REPO_CAP_COMPONENTS
    old_components = cfg["max_stride_components"]
    if new_components >= old_components:
        return {}
    new_label = (
        f"{cfg['assessment_depth']} (components: {new_components} — "
        f"capped from {old_components} on large repo: {src_count} source files, "
        f"STRIDE turns: {cfg['stride_turns_simple']}/"
        f"{cfg['stride_turns_moderate']}/{cfg['stride_turns_complex']}, "
        f"diagrams: {cfg['diagram_depth']}, QA: {cfg['qa_depth']})"
    )
    return {
        "max_stride_components": new_components,
        "depth_label": new_label,
        "repo_size_capped": True,
        "repo_size_source_files": src_count,
    }


def resolve_default_tier_for_capped_repos(cfg: dict,
                                           ns: argparse.Namespace) -> dict:
    """B2d — auto-switch reasoning tier on capped large repos.

    Triggers only when ALL of the following hold:
      * user did NOT pass ``--reasoning-model`` on the CLI (resolution
        silently picked the depth default — opus-cheap at standard/thorough)
      * ``repo_size_capped`` is True (set by resolve_repo_size_cap when
        source-file count exceeds LARGE_REPO_SOURCE_FILE_THRESHOLD at
        ``--assessment-depth standard``)
      * the silently-resolved tier is ``opus-cheap`` (the only tier where
        switching to ``haiku-economy`` produces real savings — quick already
        defaults to haiku-economy, opus is an explicit user choice)

    On trigger: switch reasoning_model to ``haiku-economy`` and re-run the
    dependent resolvers (reasoning_model, extended_models, stride_profile)
    so the resulting cfg is internally consistent.

    Rationale: the large-repo cap reduces ``MAX_STRIDE_COMPONENTS`` to 3,
    which keeps the merger/triage workload small enough that paying Opus
    rates per-token is uneconomical (Phase 9 merger handles ≤45 threats,
    Phase 10b triage runs deterministically since M3.1). Haiku-economy
    keeps STRIDE on Sonnet (the value-creating phase) and downgrades only
    merger + qa-routine where Sonnet/Haiku is sufficient.

    Override path: pass any explicit ``--reasoning-model`` flag to opt out
    of the auto-switch (this resolver does not run when ns.reasoning_model
    is set).
    """
    if ns.reasoning_model:                            # explicit user choice — never override
        return {}
    if not cfg.get("repo_size_capped"):
        return {}
    if cfg.get("reasoning_model") != "opus-cheap":   # only the opus-cheap → haiku-economy path
        return {}

    depth = cfg["assessment_depth"]

    # Re-run the same resolvers we ran initially, but with the new tier.
    # Build a synthetic ns that records the implicit tier choice so
    # resolve_reasoning_model treats it as user-selected.
    import copy
    ns_synth = copy.copy(ns)
    ns_synth.reasoning_model = "haiku-economy"

    patch: dict = {}
    patch.update(resolve_reasoning_model(ns_synth, depth))
    patch.update(resolve_extended_models("haiku-economy", depth))
    patch.update(resolve_stride_profile("haiku-economy", depth))

    # Override the label so the auto-switch is visible in --config-summary.
    patch["reasoning_label"] = (
        f"haiku-economy (auto — large repo capped to "
        f"{cfg['max_stride_components']} components, "
        f"Opus on merger/triage uneconomical at this scale)"
    )
    patch["reasoning_auto_switched"] = True
    return patch


def resolve_reasoning_model(ns: argparse.Namespace, depth: str) -> dict:
    """Resolution order: env-vars → --reasoning-model → depth default.

    Defaults per depth:
      • quick    → haiku-economy (deterministic-leaning agents on Haiku;
                   Reasoning core stays on Sonnet)
      • standard → opus-cheap
      • thorough → opus-cheap

    Override with ``--reasoning-model sonnet`` to keep all agents on
    Sonnet at quick (pre-2026-05 behaviour). Env vars
    (APPSEC_STRIDE_MODEL / APPSEC_TRIAGE_MODEL / APPSEC_MERGER_MODEL)
    take highest precedence for fine-grained overrides.

    The ``haiku-economy`` tier keeps STRIDE/triage/merger on Sonnet
    (Threat-Reasoning is the tool's primary value contribution and
    must not be downgraded). The Haiku savings come from the
    deterministic-leaning agents (context-resolver, recon-scanner,
    qa-routine fixes, config-scanner) — see resolve_extended_models.
    """
    # Step 1: pick the base mode.
    if ns.reasoning_model:
        mode = ns.reasoning_model
    elif depth == "quick":
        mode = "haiku-economy"
    else:
        mode = "opus-cheap"

    models = dict(MODEL_MATRIX[mode])

    # Step 2: punctual override from --stride-model (deprecated alias).
    if ns.stride_model:
        models["stride"] = ns.stride_model

    # Step 3: env var highest precedence.
    env_map = {
        "stride": "APPSEC_STRIDE_MODEL",
        "triage": "APPSEC_TRIAGE_MODEL",
        "merger": "APPSEC_MERGER_MODEL",
    }
    for k, env in env_map.items():
        if os.environ.get(env):
            models[k] = os.environ[env]

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
    if reasoning_mode == "haiku-economy":
        models = dict(EXTENDED_MODEL_MATRIX[("haiku-economy", depth)])
    else:
        models = dict(_DEFAULT_EXTENDED_ROUTING)

    env_map = {
        "context_resolver": "APPSEC_CONTEXT_RESOLVER_MODEL",
        "recon_scanner":    "APPSEC_RECON_SCANNER_MODEL",
        "qa_routine":       "APPSEC_QA_ROUTINE_MODEL",
        "qa_content":       "APPSEC_QA_CONTENT_MODEL",
        "config_scanner":   "APPSEC_CONFIG_SCANNER_MODEL",
        "orchestrator":     "APPSEC_ORCHESTRATOR_MODEL",
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
    }


def resolve_stride_profile(reasoning_mode: str, depth: str) -> dict:
    """Return the STRIDE-analyzer depth profile.

    The STRIDE depth-reduction (A-F) is gated on
    ``reasoning_mode == haiku-economy`` AND ``depth == quick``.
    Both conditions must hold to keep behaviour predictable for users
    who pick haiku-economy at standard/thorough (no STRIDE reduction
    there) and for users who explicitly pick a non-haiku tier at quick
    (e.g. ``--reasoning-model sonnet``, which preserves the pre-2026-05
    "Sonnet everywhere at quick" behaviour).

    Since 2026-05 ``haiku-economy`` is also the default at quick depth,
    so an unflagged ``--assessment-depth quick`` invocation activates
    the A-F profile automatically — no extra flag required.

    Quick + haiku-economy applies:
      A. Skip verification greps
      B. Cap threats per STRIDE category at 2 (was "2-5")
      C. Omit code_example field in remediation
      D. Omit evidence excerpt (file:line stays)
      E. Skip CVSS v4.0 scoring
      F. Lower TURN_BUDGET hard cap from 40 to 25

    The model itself stays Sonnet — only the task scope is reduced.
    """
    if reasoning_mode == "haiku-economy" and depth == "quick":
        profile = dict(QUICK_STRIDE_PROFILE)
        profile["stride_profile_label"] = "quick (depth-reduced via haiku-economy)"
        return {"stride_profile": profile}
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
    """LLM enrichment of architecture-diagrams.md and security-architecture.md
    fragments.

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

    # Model resolution — default opus when on, override via flag or env.
    if ns.architect_model == "sonnet":
        model = "claude-sonnet-4-6"
    elif ns.architect_model == "opus":
        model = "claude-opus-4-7"
    else:
        model = "claude-opus-4-7"  # default
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

    # Try to resolve the git root; fall back to the given path if not a repo.
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
                              dry_run: bool) -> dict:
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
    p.add_argument("--with-sca",  action="store_true")
    p.add_argument("--keep-runtime-files", action="store_true")
    p.add_argument("--verbose",   action="store_true")
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
                   choices=("sonnet", "opus-cheap", "opus", "haiku-economy"))
    p.add_argument("--stride-model", default=None)
    p.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"))
    # Convenience shortcuts: --quick / --thorough for the two non-default
    # depth levels. Mapped to --assessment-depth in resolve() below.
    # Mutually exclusive with --assessment-depth and with each other —
    # detect_conflicts() raises on collision.
    p.add_argument("--quick",    action="store_true",
                   help="Shortcut for --assessment-depth quick.")
    p.add_argument("--thorough", action="store_true",
                   help="Shortcut for --assessment-depth thorough.")
    # Architect
    p.add_argument("--architect-review",   action="store_true")
    p.add_argument("--no-architect-review", action="store_true")
    p.add_argument("--architect-model",    choices=("sonnet", "opus"))
    # Architecture-fragment enrichment (M3.3 / D2). On by default at standard
    # and thorough; off at quick since 2026-05.
    p.add_argument("--no-enrich-arch", action="store_true",
                   dest="no_enrich_arch",
                   help="Disable LLM enrichment of architecture-diagrams.md and "
                        "security-architecture.md fragments (on by default at "
                        "standard/thorough).")
    p.add_argument("--enrich-arch", action="store_true",
                   dest="enrich_arch",
                   help="Force LLM enrichment of architecture fragments at any "
                        "depth (overrides the quick-depth default-off).")
    # v2 13-section §7 layout — DEFAULT since 2026-05.
    # v2 restructures §7 around security-control categories and lists
    # findings only where the affected control is described.
    # See `data/sections-contract.yaml → schema_v2` for the full layout
    # + finding routing map.
    #
    # `--schema-v2` is kept as a no-op alias so explicit declarations in
    # CI scripts do not break; `--schema-v1` is the opt-out for legacy
    # threat-models that should not be migrated.
    p.add_argument("--schema-v2", action="store_true",
                   dest="schema_v2",
                   help="Explicitly request the 13-section §7 security "
                        "architecture layout. No-op since 2026-05 — v2 is the "
                        "default. Kept for forward compatibility with CI "
                        "scripts that declare schema preference.")
    p.add_argument("--schema-v1", action="store_true",
                   dest="schema_v1",
                   help="Opt out of the v2 13-section §7 layout and use "
                        "the legacy 14-section layout. Recommended only "
                        "when updating a threat-model that was authored "
                        "against the v1 contract and is not yet migrated.")
    # Walkthroughs opt-out (2026-05). Stage 2 normally authors
    # `attack-walkthroughs.md` (sequence diagrams per Critical) — costs
    # ~1 min in quick depth, more in thorough. Skipping renders §3 with
    # the deterministic chain-overview only, no per-finding sequence
    # diagrams. Useful for CI / regression / fast iteration.
    p.add_argument("--no-walkthroughs", action="store_true",
                   dest="no_walkthroughs",
                   help="Skip authoring attack-walkthroughs.md in Stage 2; "
                        "§3 falls back to chain-overview-only rendering.")
    # PR / base / no-qa / qa-scan-repo
    p.add_argument("--base",         default=None)
    p.add_argument("--pr-mode",      action="store_true")
    p.add_argument("--no-qa",        action="store_true")
    p.add_argument("--qa-scan-repo", action="store_true")
    # Scan manifest — log all scanned files to OUTPUT_DIR/.scan-manifest.txt
    p.add_argument("--scan-manifest", action="store_true")
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
    p.add_argument("--no-sca", action="store_true", dest="no_sca",
                   help="Disable SCA scan even if a preset enables it.")
    p.add_argument("--no-pdf", action="store_true", dest="no_pdf",
                   help="Disable PDF export even if a preset enables it.")

    # Org-profile selection flags. These are consumed by resolve_org_profile.
    # The resolver merges the resulting defaults below CLI flags.
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
        "with_sca":        ns.with_sca,
        "keep_runtime_files": ns.keep_runtime_files,
        "verbose":         ns.verbose,
        "tracing":         ns.tracing,
        "resume":          ns.resume,
        "pr_mode":         ns.pr_mode,
        "base_ref":        ns.base,
        "qa_scan_repo":    ns.qa_scan_repo,
        "scan_manifest":   ns.scan_manifest,
        "no_confirm":      ns.no_confirm,
    }

    cfg.update(resolve_write_yaml(ns))
    cfg.update(resolve_requirements(ns, read_requirements_config(plugin_root)))

    depth_info = resolve_assessment_depth(ns)
    cfg.update(depth_info)

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
        cfg["reasoning_model"], depth_info["assessment_depth"]
    ))
    cfg.update(resolve_architect_review(
        ns, depth_info["assessment_depth"], ns.dry_run
    ))
    cfg.update(resolve_enrich_arch_fragments(
        ns, depth_info["assessment_depth"], ns.dry_run
    ))
    # v2 13-section schema — DEFAULT since 2026-05.
    # Resolution order:
    #   1. `--schema-v1` → v1 (explicit opt-out)
    #   2. `APPSEC_SCHEMA_V1=1` env-var → v1 (CI / scripted opt-out)
    #   3. otherwise → v2 (default)
    # `--schema-v2` and `APPSEC_SCHEMA_V2=1` are kept as explicit "yes,
    # really v2" markers but are no-ops since v2 is already the default.
    import os as _os
    _explicit_v1 = bool(getattr(ns, "schema_v1", False)) or _os.environ.get(
        "APPSEC_SCHEMA_V1", ""
    ).strip() in ("1", "true", "yes", "on")
    cfg["security_schema"] = "v1" if _explicit_v1 else "v2"
    if _explicit_v1:
        cfg["security_schema_label"] = (
            "v1 (14-section legacy layout — opt-out via --schema-v1)"
        )
    else:
        cfg["security_schema_label"] = (
            "v2 (13-section security architecture layout — default)"
        )
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
    cfg.update(resolve_paths(ns, ns.dry_run))

    # B2c — repo-size auto-cap. Must run after resolve_paths so we have
    # the final repo_root value, and after resolve_assessment_depth so we
    # know the tier.
    cfg.update(resolve_repo_size_cap(cfg, Path(cfg["repo_root"])))

    # B2d — auto-switch reasoning tier on capped large repos. Must run
    # after resolve_repo_size_cap (depends on `repo_size_capped`) and
    # silently no-ops when ns.reasoning_model is set.
    cfg.update(resolve_default_tier_for_capped_repos(cfg, ns))

    cfg.update(resolve_incremental_mode(
        ns, Path(cfg["output_dir"]), ns.dry_run
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

    # RC.A — emit `total_stages` deterministically so the skill banner does
    # not have to compute it from prose in SKILL-impl.md. Formula:
    #   2 (Stage 1 + Stage 2)
    #   + 1 when QA runs (not SKIP_QA and not DRY_RUN)
    #   + 1 when Architect Review runs (architect_review and not DRY_RUN)
    cfg["total_stages"] = _compute_total_stages(cfg)

    return cfg


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
    org_block["with_sca"] = _resolve_bool(
        ns.with_sca, ns.no_sca, defaults.get("with_sca"), cfg["with_sca"]
    )

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
    lines = [_box_heading("Threat Model — Pre-flight", width)]

    verdict = _run_plan_verdict(cfg, pre_check, dirty_set, compat_label)

    # --- Section: Target ---
    lines.extend(_box_section("Target", width))
    lines.extend(_box_kv("Repository", cfg["repo_root"], width))
    lines.extend(_box_kv("Output", cfg["output_dir"], width))

    # --- Section: Plugin ---
    lines.append(_box_line(width=width))
    lines.extend(_box_section("Plugin", width))
    lines.extend(_box_kv(
        "Version",
        f"appsec-advisor {cfg['plugin_version']} "
        f"(analysis v{cfg['analysis_version']})",
        width,
    ))
    if pre_check:
        ver = pre_check.get("plugin_version", {}) or {}
        baseline_v = ver.get("baseline")
        tier = ver.get("tier")
        if baseline_v and baseline_v != cfg["plugin_version"]:
            drift_marker = "  ⚠ DRIFT" if tier in ("minor", "major") else ""
            lines.extend(_box_kv(
                "Baseline",
                f"{baseline_v} (tier={tier}){drift_marker}",
                width,
            ))
    if compat_label and compat_label not in ("equal", None, ""):
        lines.extend(_box_kv("Schema", f"analysis_version drift: {compat_label}", width))
    lines.extend(_box_kv("Mode", verdict["mode_line"], width))

    # --- Section: Decision ---
    lines.append(_box_line(width=width))
    lines.extend(_box_section("Decision", width))
    lines.extend(_box_kv("Verdict", verdict["verdict"], width))
    lines.extend(_box_kv("Pipeline", verdict["pipeline"], width))
    if verdict.get("reason"):
        lines.extend(_box_kv("Reason", verdict["reason"], width))

    # --- Section: Files / Components (only when pre-check ran) ---
    if pre_check:
        sec_count = pre_check.get("security_relevant_change_count", 0)
        noise_count = len(pre_check.get("noise_only_changes", []) or [])
        excluded = pre_check.get("excluded_pre_filter_count", 0)
        total = sec_count + noise_count + excluded
        if total or sec_count or excluded:
            lines.append(_box_line(width=width))
            lines.extend(_box_section("Files", width))
            lines.extend(_box_kv("Total seen", str(total), width))
            lines.extend(_box_kv(
                "Excluded", f"{excluded} (plugin output / scan-excludes)", width,
            ))
            lines.extend(_box_kv(
                "Noise", f"{noise_count} (docs / format-only / non-security)", width,
            ))
            lines.extend(_box_kv("Relevant", str(sec_count), width))

        if dirty_set is not None:
            known = len(dirty_set.get("all_components_known", []) or [])
            dirty_ids = dirty_set.get("dirty_component_ids", []) or []
            carry = max(0, known - len(dirty_ids))
            lines.extend(_box_kv(
                "Components",
                f"{known} known, {len(dirty_ids)} dirty"
                + (f" ({', '.join(dirty_ids[:5])})" if dirty_ids else "")
                + f", {carry} carried forward",
                width,
            ))

    # --- Section: Why (file list with reasons) ---
    if pre_check:
        sec_files = pre_check.get("security_relevant_changes", []) or []
        reasons = pre_check.get("relevance_reasons", {}) or {}
        if sec_files:
            lines.append(_box_line(width=width))
            header = (
                "Why this run is going to launch"
                if verdict["will_run"] else
                "Why this run will NOT execute Stage 1+2+3"
            )
            lines.extend(_box_section(header, width))
            for f in sec_files[:6]:
                rs = reasons.get(f, [])
                rs_short = ", ".join(rs[:3]) if rs else "no reason recorded"
                lines.extend(_box_bullet(f"{f}  [{rs_short}]", width))
            if len(sec_files) > 6:
                lines.extend(_box_bullet(f"... and {len(sec_files) - 6} more", width))

        # When dirty-set returned ambiguous (potential new component),
        # surface the unmapped files so the user knows what to expect.
        if dirty_set and dirty_set.get("decision") == "ambiguous_potential_new_component":
            unmapped = dirty_set.get("unmapped_files", []) or []
            if unmapped:
                lines.append(_box_line(width=width))
                lines.extend(_box_section("Unmapped (possible new component)", width))
                for u in unmapped[:6]:
                    lines.extend(_box_bullet(u, width))

    # --- Section: Configuration (only when pipeline will actually run) ---
    if verdict["will_run"]:
        lines.append(_box_line(width=width))
        lines.extend(_box_section("Configuration", width))
        lines.extend(_box_kv("Depth", _format_depth_summary(cfg), width))
        lines.extend(_box_kv("Reasoning", _format_reasoning_summary(cfg), width))
        active = _summary_active_options(cfg)
        for label, value in active:
            lines.extend(_box_kv(label, value, width))

    # --- Section: Notes / Recommendations ---
    notes = _run_plan_notes(verdict, cfg, pre_check, dirty_set, compat_label)
    if notes:
        lines.append(_box_line(width=width))
        lines.extend(_box_section("Notes", width))
        for n in notes:
            lines.extend(_box_bullet(n, width))

    lines.append(_box_footer(width))
    return "\n".join(lines) + "\n"


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
            reason = "no prior threat-model.yaml in output dir"
        elif baseline_state == "legacy":
            reason = "legacy threat-model.md without yaml — bootstrap full run"
        else:
            reason = "user requested --full (or --dry-run forces full)"
        return {
            "verdict":   "RUN — full assessment",
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


def _run_plan_notes(
    verdict: dict,
    cfg: dict,
    pre_check: dict | None,
    dirty_set: dict | None,
    compat_label: str | None,
) -> list[str]:
    """Notes / recommendations to surface below the box."""
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
            f"STRIDE component count capped at {cfg.get('max_stride_components')} "
            f"(would have been 5) due to large repo "
            f"({cfg.get('repo_size_source_files')} source files)."
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

    The ``max_stride_components`` cap is suppressed for incremental runs
    because it is meaningless there: the dirty-set defines the scope, and
    the cap only governs Phase-1 component DETECTION which incremental
    skips. Showing "up to 8 components" while we re-analyze 1 is
    actively misleading. The Files block of the box already shows the
    actual ``N known, M dirty`` counts.
    """
    parts: list[str] = [cfg.get("assessment_depth", "standard")]
    if not cfg.get("incremental"):
        parts.append(f"up to {cfg.get('max_stride_components', '?')} components")
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
    mode = cfg.get("reasoning_model") or "unknown"
    if cfg.get("reasoning_auto_switched"):
        return f"{mode}; auto-switched for large repo; STRIDE Sonnet"
    if mode == "haiku-economy":
        return "haiku-economy; cheap phases Haiku; STRIDE/triage/merge Sonnet"

    def short(model: str | None) -> str:
        raw = (model or "unknown").replace("claude-", "")
        return (
            raw.replace("sonnet-4-6", "Sonnet")
            .replace("opus-4-7", "Opus")
            .replace("haiku-4-5", "Haiku")
        )

    return (
        f"{mode}; STRIDE {short(cfg.get('stride_model'))}; "
        f"triage {short(cfg.get('triage_model'))}; "
        f"merge {short(cfg.get('merger_model'))}"
    )


def _summary_active_options(cfg: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []

    outputs = _format_outputs_summary(cfg)
    if outputs:
        rows.append(("Outputs", outputs))

    extras: list[str] = []
    if cfg.get("check_requirements"):
        extras.append(f"requirements ({cfg['requirements_label']})")
    if cfg.get("with_sca"):
        extras.append("SCA")
    if cfg.get("architect_review"):
        extras.append(f"architect review ({cfg['architect_label']})")
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
    if skips:
        rows.append(("Skips", ", ".join(skips)))

    flags = _format_run_flags(cfg)
    if flags:
        rows.append(("Run flags", flags))

    sp_label = (cfg.get("stride_profile") or {}).get(
        "stride_profile_label", "full"
    )
    if sp_label != "full":
        rows.append(("STRIDE", sp_label))

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
            f"Note: STRIDE component count capped at {cfg['max_stride_components']} "
            f"(would have been 5) because the repository is large "
            f"({cfg['repo_size_source_files']} source files). Pass "
            f"--assessment-depth thorough to override and analyze 8 components."
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
    pre_check_path: str | None = None
    dirty_set_path: str | None = None
    compat_label: str | None = None
    if run_plan_flag:
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
        "--run-plan",
    )]
    # Strip the run-plan companion flags + their values too.
    if run_plan_flag:
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

    if run_plan_flag:
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
        print(render_run_plan(cfg, pre_check, dirty_set, compat_label), end="")
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
