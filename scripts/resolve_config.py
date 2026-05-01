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
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
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
        "triage": "claude-opus-4-7",
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
    # haiku-economy: depth-conditional Haiku-Routing
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
        "recon_scanner":    SONNET,
        "qa_routine":       HAIKU,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
    },
    ("haiku-economy", "thorough"): {
        "context_resolver": HAIKU,
        "recon_scanner":    SONNET,
        "qa_routine":       SONNET,
        "qa_content":       SONNET,
        "config_scanner":   HAIKU,
        "orchestrator":     SONNET,
    },
}

# Default-Routing für sonnet/opus-cheap/opus — alles Sonnet (= heutiges Verhalten).
_DEFAULT_EXTENDED_ROUTING = {
    "context_resolver": SONNET,
    "recon_scanner":    SONNET,
    "qa_routine":       SONNET,
    "qa_content":       SONNET,
    "config_scanner":   SONNET,
    "orchestrator":     SONNET,
}

# Quick-Mode STRIDE-Tiefe-Reduktion (A-F). Modell bleibt Sonnet — reduziert
# wird nur der Aufgabenumfang. Greift unabhängig von der Reasoning-Tier
# wenn assessment_depth == "quick".
QUICK_STRIDE_PROFILE = {
    "skip_verification_greps": True,   # A
    "max_threats_per_category": 2,     # B
    "skip_code_examples": True,        # C
    "skip_evidence_excerpt": True,     # D
    "skip_cvss_scoring": True,         # E
    "turn_budget_hard_cap": 25,        # F (war 40)
}

DEPTH_PARAMS = {
    "quick":    {"components": 3, "simple": 10, "moderate": 15, "complex": 20,
                 "diagrams": "minimal",  "qa": "core"},
    "standard": {"components": 5, "simple": 15, "moderate": 22, "complex": 31,
                 "diagrams": "standard", "qa": "full"},
    "thorough": {"components": 8, "simple": 20, "moderate": 28, "complex": 35,
                 "diagrams": "extended", "qa": "extended"},
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
             f"diagrams: {params['diagrams']}, QA: {params['qa']})")
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
    routine + content), config-scanner, and the orchestrator. Default
    behaviour for ``sonnet``/``opus-cheap``/``opus`` is identical to
    today (everything Sonnet). The new ``haiku-economy`` tier routes
    deterministic-leaning agents to Haiku — the routing depends on
    ``depth`` because Quick mode has a wider Haiku surface than
    Standard/Thorough.

    Env vars (APPSEC_<AGENT>_MODEL) override per-agent for ad-hoc
    debugging.
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


def resolve_enrich_arch_fragments(ns: argparse.Namespace, depth: str,
                                   dry_run: bool) -> dict:
    """LLM enrichment of architecture-diagrams.md and security-architecture.md
    fragments is on by default for all depths.

    Default behaviour:

      • all depths → enrich (Stage 2 LLM rewrites the two fragments)
      • dry-run → never enrich (transient output anyway)

    User override:

      • ``--no-enrich-arch`` forces off at any depth

    Token cost when enabled: ~25-30k input + ~5-8k output (~$0.50-1.00 at
    sonnet-4-6) on top of the standard Stage 2 budget.
    """
    if dry_run:
        return {"enrich_arch_fragments": False,
                "enrich_arch_label": "disabled (dry-run)"}
    if getattr(ns, "no_enrich_arch", False):
        return {"enrich_arch_fragments": False,
                "enrich_arch_label": "disabled (--no-enrich-arch)"}
    return {"enrich_arch_fragments": True,
            "enrich_arch_label": "enabled (default)"}


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
    """Return ``requirements_source.enabled`` from the check-appsec-requirements
    skill config. Missing file / unparseable JSON → ``False``."""
    cfg = plugin_root / "skills" / "check-appsec-requirements" / "config.json"
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
    p.add_argument("--tracing",   action="store_true")
    # Paths
    p.add_argument("--repo",   default=None)
    p.add_argument("--output", default=None)
    # Models / depth
    p.add_argument("--reasoning-model",
                   choices=("sonnet", "opus-cheap", "opus", "haiku-economy"))
    p.add_argument("--stride-model", default=None)
    p.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"))
    # Architect
    p.add_argument("--architect-review",   action="store_true")
    p.add_argument("--no-architect-review", action="store_true")
    p.add_argument("--architect-model",    choices=("sonnet", "opus"))
    # Architecture-fragment enrichment (M3.3 / D2). On by default for all depths.
    p.add_argument("--no-enrich-arch", action="store_true",
                   dest="no_enrich_arch",
                   help="Disable LLM enrichment of architecture-diagrams.md and "
                        "security-architecture.md fragments (on by default).")
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

    err = detect_conflicts(ns)
    if err:
        raise SystemExit(f"Error: {err}")

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
        "skip_qa":         ns.no_qa or os.environ.get("APPSEC_SKIP_QA") == "1",
        "qa_scan_repo":    ns.qa_scan_repo,
        "scan_manifest":   ns.scan_manifest,
        "no_confirm":      ns.no_confirm,
    }

    cfg.update(resolve_write_yaml(ns))
    cfg.update(resolve_requirements(ns, read_requirements_config(plugin_root)))

    depth_info = resolve_assessment_depth(ns)
    cfg.update(depth_info)

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
    cfg.update(resolve_paths(ns, ns.dry_run))

    # B2c — repo-size auto-cap. Must run after resolve_paths so we have
    # the final repo_root value, and after resolve_assessment_depth so we
    # know the tier.
    cfg.update(resolve_repo_size_cap(cfg, Path(cfg["repo_root"])))

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

    return cfg


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
    lines = ["Configuration resolved.", ""]
    lines.append(f"  Repository   : {cfg['repo_root']}")
    lines.append(f"  Output       : {cfg['output_dir']}")
    lines.append(
        f"  Plugin       : appsec-advisor {cfg['plugin_version']} "
        f"(analysis v{cfg['analysis_version']})"
    )
    lines.append(f"  Mode         : {cfg['mode_label']}")
    if cfg["mode"] == "incremental":
        # Baseline classification is set later by the Compat Gate; here we
        # only know the baseline_state from disk.
        lines.append(f"  Baseline     : {cfg.get('baseline_state', '?')}")
    lines.append(f"  Depth        : {cfg['depth_label']}")
    lines.append(f"  Requirements : {cfg['requirements_label']}")
    # Reasoning-tier line — only render explicitly when haiku-economy is
    # active (signals the opt-in cost-economy routing). Other tiers retain
    # today's behaviour (no Reasoning line; reasoning_label is logged
    # downstream via .skill-config.json for record-keeping).
    if cfg.get("reasoning_model") == "haiku-economy":
        stride_label = (cfg.get("stride_profile") or {}).get(
            "stride_profile_label", "full"
        )
        lines.append(
            f"  Reasoning    : haiku-economy "
            f"(context/recon/qa-routine/config-scanner → Haiku 4.5; "
            f"STRIDE/triage/merger → Sonnet 4.6)"
        )
        lines.append(f"  STRIDE Prof. : {stride_label}")
    if cfg.get("architect_review"):
        lines.append(f"  Architect    : {cfg['architect_label']}")
    # M11/M9 — wall-time + cost deadline display
    deadline_parts = []
    if cfg.get("max_wall_time_seconds"):
        sec = cfg["max_wall_time_seconds"]
        if sec >= 3600:
            deadline_parts.append(f"wall-time {sec // 3600} h {(sec % 3600) // 60} min".replace(" 0 min", ""))
        else:
            deadline_parts.append(f"wall-time {sec // 60} min")
    if cfg.get("max_cost_usd"):
        deadline_parts.append(f"cost ${cfg['max_cost_usd']:.2f}")
    if deadline_parts:
        lines.append(f"  Deadline     : {' / '.join(deadline_parts)}")

    post_lines = []
    if cfg.get("output_outside_repo"):
        post_lines.append(
            "  Note: output directory is outside the repository — "
            ".gitignore entries will be skipped."
        )
    if cfg.get("post_summary_note"):
        post_lines.append(f"  {cfg['post_summary_note']}")
    if cfg.get("mode") == "incremental":
        post_lines.append(
            f"  Recommendation: Run with --full periodically to ensure "
            f"complete coverage with plugin v{cfg['plugin_version']}."
        )
    if not cfg.get("check_requirements") \
            and cfg["requirements_label"].startswith("disabled (config)"):
        post_lines.append(
            "  Tip: requirements compliance is disabled. Pass --requirements "
            "or set requirements_yaml_url in "
            "skills/check-appsec-requirements/config.json to enable."
        )
    if cfg.get("repo_size_capped"):
        post_lines.append(
            f"  Note: STRIDE component count capped at {cfg['max_stride_components']} "
            f"(would have been 5) because the repository is large "
            f"({cfg['repo_size_source_files']} source files). Pass "
            f"--assessment-depth thorough to override and analyze 8 components."
        )
    if post_lines:
        lines.append("")
        lines.extend(post_lines)

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    plugin_root = Path(__file__).resolve().parent.parent

    # Separate ``--emit-file`` / ``--config-summary`` meta flags from the
    # user argv before it reaches the resolver's argparser, so that
    # scope-word parsing isn't polluted by them.
    emit_file_flag     = "--emit-file" in argv
    config_summary     = "--config-summary" in argv
    filtered = [a for a in argv if a not in ("--emit-file", "--config-summary")]

    cfg = resolve(filtered, plugin_root)

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
