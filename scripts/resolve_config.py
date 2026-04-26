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


def resolve_reasoning_model(ns: argparse.Namespace, depth: str) -> dict:
    """Resolution order: env-vars → --reasoning-model → depth default.

    Quick depth → sonnet. Anything else → opus-cheap. Env vars
    (APPSEC_STRIDE_MODEL / APPSEC_TRIAGE_MODEL / APPSEC_MERGER_MODEL)
    take highest precedence for fine-grained overrides.
    """
    # Step 1: pick the base mode.
    if ns.reasoning_model:
        mode = ns.reasoning_model
    elif depth == "quick":
        mode = "sonnet"
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
    p.add_argument("--reasoning-model", choices=("sonnet", "opus-cheap", "opus"))
    p.add_argument("--stride-model", default=None)
    p.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"))
    # Architect
    p.add_argument("--architect-review",   action="store_true")
    p.add_argument("--no-architect-review", action="store_true")
    p.add_argument("--architect-model",    choices=("sonnet", "opus"))
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
    cfg.update(resolve_architect_review(
        ns, depth_info["assessment_depth"], ns.dry_run
    ))
    cfg.update(resolve_paths(ns, ns.dry_run))

    cfg.update(resolve_incremental_mode(
        ns, Path(cfg["output_dir"]), ns.dry_run
    ))

    # Plugin metadata (always present).
    cfg["plugin_root"]   = str(plugin_root)
    cfg["plugin_version"] = _read_plugin_version(plugin_root)
    cfg["analysis_version"] = _read_analysis_version(plugin_root)

    return cfg


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
    if cfg.get("architect_review"):
        lines.append(f"  Architect    : {cfg['architect_label']}")

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
