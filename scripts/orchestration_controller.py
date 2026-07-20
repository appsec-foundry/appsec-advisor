#!/usr/bin/env python3
"""Deterministic control-plane helpers for the threat-model skill.

The controller owns full/rebuild preflight state mutations and emits a compact,
schema-validated action.  It never invokes Claude Agent/Task tools; the thin
skill runtime remains responsible for those calls.

Commands:

    orchestration_controller.py route -- <create-threat-model arguments>
    orchestration_controller.py prepare [--force] -- <arguments>
    orchestration_controller.py post-stage1 --output-dir <path>
    orchestration_controller.py prepare-abuse --output-dir <path>
    orchestration_controller.py finalize-abuse --output-dir <path>
    orchestration_controller.py prepare-stage2 --output-dir <path>
    orchestration_controller.py next --output-dir <path>
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import check_permissions  # noqa: E402
import detect_session_model  # noqa: E402
import resolve_config  # noqa: E402
from event_log import format_line  # noqa: E402

ACTION_SCHEMA = PLUGIN_ROOT / "schemas" / "orchestration-action.schema.json"
THIN_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md"
THIN_RERENDER_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md"
THIN_STAGE1_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1.md"
THIN_STAGE1C_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1c.md"
THIN_STAGE2_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage2.md"
LEGACY_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"

_FULL_INTERMEDIATE_NAMES = {
    ".threats-merged.json",
    ".triage-flags.json",
    ".architect-review.md",
    ".recon-summary.md",
    ".appsec-checkpoint",
    ".assessment-summary-emitted",
    ".phase-epoch",
    ".session-agent-map",
    ".prior-findings-index.json",
    ".pre-render-repair-plan.json",
    ".qa-repair-plan.json",
    ".architect-repair-plan.json",
    ".stage-stats.jsonl",
    ".run-issues.json",
    ".run-issues-fixes.json",
    ".preserved-provenance.json",
    ".dispatch-waves.json",
}
_FULL_INTERMEDIATE_GLOBS = (".stride-*.json", ".merge-*.json")

_REBUILD_NAMES = {
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "threat-model.pdf",
    "threat-model.html",
    "pentest-tasks.yaml",
    ".architect-review.md",
    ".threat-modeling-context.md",
    ".recon-summary.md",
    ".sca-practice-findings.json",
    ".known-bad-libs-findings.json",
    ".threats-merged.json",
    ".triage-flags.json",
    ".appsec-checkpoint",
    ".pre-render-repair-plan.json",
    ".qa-repair-plan.json",
    ".qa-content-repair-plan.json",
    ".architect-repair-plan.json",
    ".stage-stats.jsonl",
    ".direct-write-blocked",
    ".phase-epoch",
    ".session-agent-map",
    ".assessment-summary-emitted",
    ".skill-config.json",
    ".recon-patterns.json",
    ".compose-stats.json",
    ".context-resolver.stdout",
    ".ctx-resolver.pid",
    ".recon-scanner.pid",
    ".recon-scanner.stdout",
    ".coverage-gaps.json",
    ".dispatch-waves.json",
    ".scan-manifest.txt",
    ".requirements.yaml",
    ".prior-findings-index.json",
    ".stage1-resume-count",
    ".triage-ranking.json",
    ".run-issues.json",
    ".run-issues-fixes.json",
}
_REBUILD_GLOBS = (
    "threat-model.figure*.svg",
    "threat-model-*.md",
    "threat-model-*.yaml",
    "threat-model-*.sarif.json",
    "threat-model-*.pdf",
    "threat-model-*.html",
    "threat-model-*.figure*.svg",
    "pentest-tasks-*.yaml",
    ".stride-*.json",
    ".merge-*.json",
)
_REBUILD_DIRS = (".fragments", ".appsec-cache", ".progress", ".taxonomy-slices")
_CACHE_READ_RE = re.compile(r"\bcache_read=([0-9][0-9,]*)")

_DISPATCH_KEYS = (
    "repo_root",
    "output_dir",
    "scope",
    "write_yaml",
    "write_sarif",
    "write_pdf",
    "write_html",
    "write_pentest_tasks",
    "pentest_format",
    "pentest_target",
    "check_requirements",
    "requirements_url_override",
    "incremental",
    "reuse_recon_eligible",
    "run_id",
    "rebuild",
    "keep_runtime_files",
    "scan_manifest",
    "stride_model",
    "triage_model",
    "merger_model",
    "renderer_model",
    "abuse_verifier_model",
    "evidence_verifier_model",
    "evidence_verifier_max_findings",
    "context_resolver_model",
    "recon_scanner_model",
    "qa_routine_model",
    "qa_content_model",
    "config_scanner_model",
    "actor_discovery_model",
    "refresh_actor_discovery",
    "orchestrator_model",
    "stride_profile",
    "reasoning_label",
    "reasoning_model",
    "enrich_arch_fragments",
    "skip_attack_paths_authoring",
    "skip_attack_walkthroughs",
    "assessment_depth",
    "max_stride_components",
    "stride_concurrency",
    "stride_turns_simple",
    "stride_turns_moderate",
    "stride_turns_complex",
    "diagram_depth",
    "qa_depth",
    "verbose",
    "quiet",
    "tracing",
    "pr_mode",
    "base_ref",
    "slug",
    "total_stages",
    "plugin_version",
    "analysis_version",
    "skip_qa",
    "architect_review",
    "architect_model",
    "skip_abuse_case_verification",
    "max_repair_iterations",
    "max_wall_time_seconds",
    "max_cost_usd",
)
_DISPATCH_EXTRA_KEYS = (
    "actor_discovery_model",
    "compat_label",
    "estimate_source",
    "estimate_stage1_min",
    "estimate_stage2_min",
    "estimate_stage3_min",
    "estimate_stage4_min",
    "estimate_total_pretty",
    "invocation_args",
    "live_phase",
    "org_profile_path",
    "parallel_stride",
    "parallel_stride_env",
    "plugin_root",
    "refresh_actor_discovery",
    "reuse_recon_eligible",
)


class ControllerError(RuntimeError):
    """A deterministic preflight failure with a stable exit code."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


def _validate_action(action: dict[str, Any]) -> dict[str, Any]:
    schema = json.loads(ACTION_SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(action),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise ControllerError(f"internal action-manifest validation failed: {detail}")
    return action


def _emit(action: dict[str, Any]) -> int:
    try:
        action = _validate_action(action)
    except ControllerError as exc:
        action = {
            "schema_version": 1,
            "action": "abort",
            "reason": str(exc),
            "exit_code": exc.exit_code,
        }
    print(json.dumps(action, indent=2, sort_keys=True))
    return int(action.get("exit_code", 0)) if action["action"] == "abort" else 0


def _resolve(argv: list[str]) -> dict[str, Any]:
    filtered = [arg for arg in argv if arg != "--force"]
    return resolve_config.resolve(filtered, PLUGIN_ROOT)


def _runtime_for(cfg: dict[str, Any]) -> tuple[str, Path]:
    thin_eligible = (
        os.environ.get("APPSEC_THIN_ORCHESTRATOR") != "0"
        and not cfg.get("dry_run")
        and not cfg.get("resume")
        and not cfg.get("max_wall_time_seconds")
        and not cfg.get("max_cost_usd")
        and os.environ.get("APPSEC_LIVE_PHASE") != "1"
    )
    if thin_eligible and cfg.get("mode") in {"full", "rebuild"} and not cfg.get("rerender"):
        return "thin-full", THIN_RUNTIME
    if thin_eligible and cfg.get("mode") == "rerender":
        return "thin-rerender", THIN_RERENDER_RUNTIME
    return "legacy", LEGACY_RUNTIME


def route(argv: list[str]) -> dict[str, Any]:
    cfg = _resolve(argv)
    runtime, instruction = _runtime_for(cfg)
    if runtime == "thin-full":
        reason = "default full/rebuild compact runtime selected (opt out with APPSEC_THIN_ORCHESTRATOR=0)"
    elif runtime == "thin-rerender":
        reason = "compact rerender runtime selected (opt out with APPSEC_THIN_ORCHESTRATOR=0)"
    elif (
        cfg.get("mode") in {"full", "rebuild"}
        and not cfg.get("dry_run")
        and not cfg.get("resume")
        and not cfg.get("rerender")
        and os.environ.get("APPSEC_THIN_ORCHESTRATOR") == "0"
    ):
        reason = "compact runtime opted out via APPSEC_THIN_ORCHESTRATOR=0; using legacy parity runtime"
    else:
        reason = "special mode retains the parity runtime"
    return {
        "schema_version": 1,
        "action": "load_runtime",
        "mode": cfg["mode"],
        "runtime": runtime,
        "instruction_file": str(instruction),
        "reason": reason,
    }


def _append_event(output_dir: Path, event: str, detail: str, level: str = "INFO") -> None:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with (output_dir / ".agent-run.log").open("a", encoding="utf-8") as handle:
            handle.write(
                format_line(
                    event,
                    detail,
                    level=level,
                    component="skill-controller",
                )
            )
    except OSError:
        pass


def _run_script(
    name: str,
    args: list[str],
    *,
    acceptable: tuple[int, ...] = (0,),
    quiet: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_DIR / name), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode not in acceptable:
        detail = (completed.stderr or completed.stdout).strip()
        raise ControllerError(
            f"{name} failed with exit {completed.returncode}: {detail}",
            completed.returncode if completed.returncode > 0 else 2,
        )
    if not quiet:
        if completed.stdout:
            print(completed.stdout, end="", file=sys.stderr)
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
    return completed


def _run_external(
    command: list[str],
    *,
    acceptable: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    """Run a fixed controller-owned command and keep stdout out of context."""
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode not in acceptable:
        detail = (completed.stderr or completed.stdout).strip()
        raise ControllerError(
            f"{Path(command[0]).name} failed with exit {completed.returncode}: {detail}",
            completed.returncode if completed.returncode > 0 else 2,
        )
    return completed


def _load_run_config(output_dir: Path) -> tuple[Path, dict[str, Any]]:
    output_dir = output_dir.resolve()
    config_path = output_dir / ".skill-config.json"
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControllerError(f"cannot read resolved config {config_path}: {exc}") from exc
    return output_dir, cfg


def _persist_config(cfg: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / ".skill-config.json"
    if path.is_symlink():
        path.unlink()
    path.write_text(
        json.dumps(cfg, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    org_payload = {
        "org_profile": cfg.get("org_profile") or {},
        "preset": cfg.get("preset"),
        "defaults": cfg.get("org_profile_defaults") or {},
        "requirements_source": cfg.get("org_profile_requirements_source"),
        "llm_context_documents": cfg.get("org_profile_context_documents") or [],
        "skill_toggles": cfg.get("org_profile_skill_toggles") or {},
        "security_coach": cfg.get("org_profile_security_coach"),
    }
    org_path = output_dir / ".org-profile-effective.json"
    if org_path.is_symlink():
        org_path.unlink()
    org_path.write_text(
        json.dumps(org_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _unlink_matching(
    output_dir: Path,
    exact: set[str],
    globs: tuple[str, ...],
) -> list[str]:
    removed: list[str] = []
    if not output_dir.is_dir():
        return removed
    for path in output_dir.iterdir():
        if not path.is_file() and not path.is_symlink():
            continue
        name = path.name
        if _matches_cleanup_name(name, exact, globs):
            try:
                path.unlink()
                removed.append(name)
            except OSError:
                continue
    return sorted(removed)


def _matches_cleanup_name(
    name: str,
    exact: set[str],
    globs: tuple[str, ...],
) -> bool:
    return name in exact or any(fnmatch.fnmatchcase(name, pattern) for pattern in globs)


def _remove_dir_entry(path: Path) -> bool:
    """Remove a runtime directory or its symlink without following the link."""
    if path.is_symlink():
        try:
            path.unlink()
            return True
        except OSError:
            return False
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        return not path.exists()
    return False


def _cleanup_full(output_dir: Path) -> list[str]:
    removed = _unlink_matching(
        output_dir,
        _FULL_INTERMEDIATE_NAMES,
        _FULL_INTERMEDIATE_GLOBS,
    )
    for name in (".progress", ".fragments"):
        path = output_dir / name
        if _remove_dir_entry(path):
            removed.append(f"{name}/")
    return sorted(removed)


def _cleanup_rebuild(output_dir: Path) -> list[str]:
    if not output_dir.is_dir():
        return []
    _run_script(
        "render_changelog_audit.py",
        ["--output-dir", str(output_dir), "--archive"],
    )
    removed = _unlink_matching(output_dir, _REBUILD_NAMES, _REBUILD_GLOBS)
    for name in _REBUILD_DIRS:
        path = output_dir / name
        if _remove_dir_entry(path):
            removed.append(f"{name}/")
    return sorted(removed)


def _checkpoint_needs_render(output_dir: Path) -> bool:
    """Return whether the durable Stage-1 checkpoint still requires rendering.

    Report-file presence is deliberately irrelevant: a prior run may have left
    a stale Markdown report beside a newer Stage-1 checkpoint.
    """
    checkpoint = output_dir / ".appsec-checkpoint"
    if not checkpoint.is_file():
        return False
    try:
        line = checkpoint.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return False
    fields = dict(token.split("=", 1) for token in line.split() if "=" in token)
    return fields.get("phase") == "10b" and fields.get("status") == "completed" and fields.get("need_render") == "true"


def _activate_markers(cfg: dict[str, Any]) -> None:
    temp = Path(os.environ.get("TMPDIR") or "/tmp")
    uid = os.getuid()
    if cfg.get("verbose"):
        (temp / f".appsec-verbose-{uid}").touch()
    if cfg.get("tracing"):
        (temp / f".appsec-tracing-{uid}").touch()


def _deactivate_markers() -> None:
    temp = Path(os.environ.get("TMPDIR") or "/tmp")
    uid = os.getuid()
    for name in (f".appsec-verbose-{uid}", f".appsec-tracing-{uid}"):
        try:
            (temp / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _prepasses(cfg: dict[str, Any], receipts: list[str]) -> None:
    repo_root = str(cfg["repo_root"])
    output_dir = str(cfg["output_dir"])
    depth = str(cfg.get("assessment_depth") or "standard")
    calls: list[tuple[str, list[str]]] = [
        ("route_inventory.py", ["--repo-root", repo_root, "--output-dir", output_dir]),
    ]
    if depth == "thorough":
        calls.append(
            (
                "database_privilege_separation.py",
                [
                    "--repo-root",
                    repo_root,
                    "--output-dir",
                    output_dir,
                    "--assessment-depth",
                    "thorough",
                ],
            )
        )
    calls.extend(
        [
            (
                "architecture_coverage_checks.py",
                ["--repo-root", repo_root, "--output-dir", output_dir, "--assessment-depth", depth],
            ),
            (
                "source_auth_scanner.py",
                ["--repo-root", repo_root, "--output-dir", output_dir, "--quiet"],
            ),
        ]
    )
    for name, args in calls:
        completed = _run_script(name, args, acceptable=(0, 1, 2))
        receipts.append(f"{name}: exit {completed.returncode}")

    output = Path(output_dir)
    route_path = output / ".route-inventory.json"
    if route_path.is_file():
        try:
            route_data = json.loads(route_path.read_text(encoding="utf-8"))
            route_count = len(route_data.get("routes") or [])
        except (OSError, json.JSONDecodeError, AttributeError):
            route_count = 0
        _append_event(
            output,
            "ROUTE_INVENTORY_PREPASS",
            f".route-inventory.json ready ({route_count} routes)",
        )
    else:
        _append_event(
            output,
            "ROUTE_INVENTORY_PREPASS",
            "route_inventory.py produced no .route-inventory.json; Phase 6 fallback remains active",
            level="WARN",
        )

    auth_path = output / ".source-auth-findings.json"
    if auth_path.is_file():
        try:
            auth_data = json.loads(auth_path.read_text(encoding="utf-8"))
            auth_count = int(auth_data.get("violations") or 0)
        except (OSError, ValueError, TypeError, json.JSONDecodeError, AttributeError):
            auth_count = 0
        _append_event(
            output,
            "SOURCE_AUTH_PREPASS",
            f".source-auth-findings.json ready ({auth_count} authz finding(s))",
        )


def _fetch_requirements(cfg: dict[str, Any]) -> None:
    args = [
        "--output-dir",
        str(cfg["output_dir"]),
        "--plugin-root",
        str(PLUGIN_ROOT),
    ]
    if cfg.get("check_requirements"):
        override = cfg.get("requirements_url_override")
        args += ["--requirements", str(override)] if override else ["--require"]
    else:
        args.append("--no-requirements")
    _run_script("fetch_requirements.py", args)


def _session_context_advisory(output_dir: Path) -> str:
    """Return a session-scoped throughput/activity advisory, never occupancy."""
    session_id = (os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or "")[:8]
    hook_log = output_dir / ".hook-events.log"
    if not session_id or not hook_log.is_file():
        return ""
    try:
        lines = hook_log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    sid_token = f"[{session_id}"
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=3)
    prior_events = 0
    last_cache_read = 0
    for line in lines:
        if sid_token not in line:
            continue
        if "SESSION_STOP" in line:
            match = _CACHE_READ_RE.search(line)
            if match:
                last_cache_read = int(match.group(1).replace(",", ""))
        try:
            timestamp = datetime.strptime(line[:20], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if timestamp < cutoff:
            prior_events += 1

    if last_cache_read >= 8_000_000:
        millions = last_cache_read / 1_000_000
        return (
            f"large reused session signal: {millions:.1f}M cumulative cache-read "
            "tokens (throughput, not resident occupancy). /clear before the scan "
            "is the lowest-cost reset."
        )
    if prior_events:
        return (
            f"non-empty session signal: {prior_events} prior event(s) in this "
            "session. /clear first for the cleanest context benchmark."
        )
    return ""


def _validator_advisory() -> str:
    """Mirror the legacy optional Mermaid-validator dependency probe."""
    if os.environ.get("APPSEC_SKIP_VALIDATOR_CHECK") == "1":
        return ""
    scripts = SCRIPT_DIR
    jsdom_ok = any(
        path.is_file()
        for path in (
            scripts / "node_modules" / "jsdom" / "package.json",
            Path("/usr/lib/node_modules/jsdom/package.json"),
        )
    )
    mermaid_ok = any(
        path.is_file()
        for path in (
            Path("/usr/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs"),
            Path("/usr/local/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs"),
            scripts
            / "node_modules"
            / "@mermaid-js"
            / "mermaid-cli"
            / "node_modules"
            / "mermaid"
            / "dist"
            / "mermaid.core.mjs",
            scripts / "node_modules" / "mermaid" / "dist" / "mermaid.core.mjs",
        )
    )
    mmdc_ok = shutil.which("mmdc") is not None
    missing = [
        name
        for name, available in (
            ("jsdom", jsdom_ok),
            ("mermaid", mermaid_ok),
            ("@mermaid-js/mermaid-cli", mmdc_ok),
        )
        if not available
    ]
    if not missing:
        return ""
    return (
        "optional Mermaid QA dependencies missing: "
        + ", ".join(missing)
        + f'. Install local parser deps with `npm install --prefix "{scripts}"`; '
        "install `@mermaid-js/mermaid-cli` globally when mmdc is missing. "
        "QA continues with regex-only fallback."
    )


def _duration_estimate(cfg: dict[str, Any]) -> dict[str, Any]:
    args = [
        "--depth",
        str(cfg["assessment_depth"]),
        "--mode",
        "rebuild" if cfg.get("rebuild") else "full",
        "--reasoning-model",
        str(cfg["reasoning_model"]),
        "--output-dir",
        str(cfg["output_dir"]),
        "--repo-root",
        str(cfg["repo_root"]),
        "--max-stride-components",
        str(cfg.get("max_stride_components") or 10),
        "--sec-change-count",
        "0",
    ]
    if cfg.get("architect_review"):
        args.append("--architect-review")
    if cfg.get("skip_qa"):
        args.append("--skip-qa")
    if cfg.get("skip_abuse_case_verification"):
        args.append("--skip-abuse-cases")
    try:
        completed = _run_script("estimate_duration.py", args)
        estimate = json.loads(completed.stdout or "{}")
    except (ControllerError, json.JSONDecodeError):
        estimate = {}
    if not isinstance(estimate, dict):
        estimate = {}
    return {
        "estimate_total_pretty": estimate.get("total_pretty", "25 min"),
        "estimate_stage1_min": estimate.get("stage1_min", 25),
        "estimate_stage2_min": estimate.get("stage2_min", 8),
        "estimate_stage3_min": estimate.get("stage3_min", 7),
        "estimate_stage4_min": estimate.get("stage4_min", 4),
        "estimate_source": estimate.get("source", "parametric"),
    }


def _dispatch_values(
    cfg: dict[str, Any],
    estimate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    values = {key: cfg.get(key) for key in _DISPATCH_KEYS}
    values["scope"] = values.get("scope") or []
    values["stride_profile"] = values.get("stride_profile") or {"stride_profile_label": "full"}
    values["reuse_recon_eligible"] = bool(values.get("reuse_recon_eligible"))
    values["refresh_actor_discovery"] = bool(values.get("refresh_actor_discovery"))
    values["actor_discovery_model"] = (
        values.get("actor_discovery_model") or os.environ.get("APPSEC_ACTOR_DISCOVERY_MODEL") or "sonnet"
    )
    org_profile = cfg.get("org_profile") or {}
    values["org_profile_path"] = org_profile.get("path") if isinstance(org_profile, dict) else None
    values.update(
        {
            "plugin_root": str(PLUGIN_ROOT),
            "parallel_stride": (
                cfg.get("mode") in {"full", "rebuild"} and os.environ.get("APPSEC_PARALLEL_STRIDE", "1") != "0"
            ),
            "parallel_stride_env": os.environ.get("APPSEC_PARALLEL_STRIDE", "unset"),
            "live_phase": (
                os.environ.get("APPSEC_LIVE_PHASE") == "1" and os.environ.get("APPSEC_PARALLEL_STRIDE", "1") == "0"
            ),
            "invocation_args": cfg.get("invocation_args", ""),
            "compat_label": "equal",
        }
    )
    values.update(estimate or _duration_estimate(cfg))
    return values


def _missing_permissions_action(cfg: dict[str, Any], repo_root: Path, output_dir: Path) -> dict[str, Any] | None:
    """Return the fixed permission abort action, if target permissions are missing."""
    required_raw = check_permissions.load_required()
    required = [
        {**item, "entry": check_permissions.expand_entry(item["entry"], repo_root, output_dir, PLUGIN_ROOT)}
        for item in required_raw
    ]
    by_scope = check_permissions.effective_allow(repo_root)
    all_granted = [rule for scope_rules in by_scope.values() for rule in scope_rules]
    missing_perms = check_permissions.diff_required(required, all_granted)
    if not missing_perms:
        return None
    entries = "\n".join(f"  {item['entry']}" for item in missing_perms)
    return {
        "schema_version": 1,
        "action": "abort",
        "mode": cfg.get("mode", "full"),
        "reason": (
            f"Missing required Claude Code permissions for this repo.\n"
            f"Run:  make setup-target REPO={repo_root}\n"
            f"then restart Claude Code and re-run the skill.\n\n"
            f"Missing entries:\n{entries}"
        ),
        "exit_code": 2,
    }


def _rerender_missing_artifacts(output_dir: Path) -> list[str]:
    """List the Stage-1 artifacts required to safely re-render an assessment."""
    missing = [
        name
        for name in ("threat-model.yaml", ".threats-merged.json", ".triage-flags.json")
        if not (output_dir / name).is_file()
    ]
    fragment_dir = output_dir / ".fragments"
    try:
        fragment_count = sum(path.is_file() for path in fragment_dir.iterdir())
    except OSError:
        fragment_count = 0
    if fragment_count < 3:
        missing.append(".fragments/(>=3)")
    return missing


def _prepare_rerender(cfg: dict[str, Any]) -> dict[str, Any]:
    """Prepare the compact rerender path without touching Stage-1 artifacts."""
    output_dir = Path(cfg["output_dir"]).resolve()
    repo_root = Path(cfg["repo_root"]).resolve()
    cfg["output_dir"] = str(output_dir)
    cfg["repo_root"] = str(repo_root)

    permission_abort = _missing_permissions_action(cfg, repo_root, output_dir)
    if permission_abort:
        return permission_abort

    missing = _rerender_missing_artifacts(output_dir)
    if missing:
        return {
            "schema_version": 1,
            "action": "abort",
            "mode": "rerender",
            "reason": (
                "--rerender needs an existing assessment to re-render. Missing under "
                f"{output_dir}: {', '.join(missing)}. Run a full assessment first; "
                "for source-code changes use --incremental or --full."
            ),
            "exit_code": 2,
        }

    cfg["run_id"] = (
        os.environ.get("CLAUDE_CODE_SESSION_ID")
        or os.environ.get("CLAUDE_SESSION_ID")
        or f"run-{int(time.time())}-{os.getpid()}"
    )
    try:
        _run_script("check_state.py", [str(output_dir), "--auto-clean"])
        lock = _run_script(
            "acquire_lock.py",
            [str(output_dir / ".appsec-lock"), f"--run-id={cfg['run_id']}"],
        )
        config_path = _persist_config(cfg, output_dir)
        _activate_markers(cfg)
        _run_script(
            "acquire_lock.py",
            [
                str(output_dir / ".appsec-lock"),
                f"--run-id={cfg['run_id']}",
                "--heartbeat",
                "--phase=skill",
                "--step=stage2-dispatch",
            ],
        )
    except (ControllerError, OSError) as exc:
        try:
            (output_dir / ".appsec-lock").unlink()
        except OSError:
            pass
        _deactivate_markers()
        if isinstance(exc, ControllerError):
            raise
        raise ControllerError(f"rerender preflight filesystem operation failed: {exc}") from exc

    first_lock_line = (lock.stdout or "").strip().splitlines()
    receipts = [first_lock_line[0] if first_lock_line else "lock acquired", "rerender artifacts verified"]
    _append_event(output_dir, "ORCHESTRATION_READY", "mode=rerender runtime=thin-rerender")
    return {
        "schema_version": 1,
        "action": "dispatch_agent",
        "mode": "rerender",
        "stage": "stage2",
        "instruction_file": str(THIN_RERENDER_RUNTIME),
        "preflight_status": str(cfg.get("preflight_status") or ""),
        "run_plan": "Re-rendering existing Stage-1 artifacts; threat analysis is skipped.",
        "config_path": str(config_path),
        "dispatch_values": _dispatch_values(cfg),
        "receipts": receipts,
    }


def prepare(argv: list[str], *, force: bool = False) -> dict[str, Any]:
    cfg = _resolve(argv)
    runtime, _ = _runtime_for(cfg)
    if runtime == "thin-rerender":
        return _prepare_rerender(cfg)
    if runtime != "thin-full":
        raise ControllerError(
            "compact prepare supports only non-dry full/rebuild runs; route this invocation through the legacy runtime"
        )

    output_dir = Path(cfg["output_dir"]).resolve()
    repo_root = Path(cfg["repo_root"]).resolve()
    cfg["output_dir"] = str(output_dir)
    cfg["repo_root"] = str(repo_root)

    # Fail fast if required CC permissions are missing rather than letting the
    # run stall on interactive prompts mid-flight.
    permission_abort = _missing_permissions_action(cfg, repo_root, output_dir)
    if permission_abort:
        return permission_abort

    # Stable per-run token so a Stage-1 agent's own lock acquisition can
    # re-acquire this controller-held lock re-entrantly instead of
    # false-blocking on it (mirrors the legacy-runtime fix in SKILL-impl.md
    # "Skill-layer lock acquisition" — the 2026-07-02 costly re-dispatch).
    cfg["run_id"] = (
        os.environ.get("CLAUDE_CODE_SESSION_ID")
        or os.environ.get("CLAUDE_SESSION_ID")
        or f"run-{int(time.time())}-{os.getpid()}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    existing_names = {path.name for path in output_dir.iterdir()}
    if cfg["mode"] == "rebuild":
        had_cleanup_state = any(
            _matches_cleanup_name(name, _REBUILD_NAMES, _REBUILD_GLOBS)
            or name in _REBUILD_DIRS
            or name in {"threat-model-changelog.md", "threat-model-changelog.jsonl"}
            for name in existing_names
        )
    else:
        had_cleanup_state = any(
            _matches_cleanup_name(
                name,
                _FULL_INTERMEDIATE_NAMES,
                _FULL_INTERMEDIATE_GLOBS,
            )
            or name in {".progress", ".fragments"}
            for name in existing_names
        )

    if cfg["mode"] == "rebuild" and _checkpoint_needs_render(output_dir) and not force:
        return {
            "schema_version": 1,
            "action": "abort",
            "mode": "rebuild",
            "reason": (
                "Stage 1 is complete (phase=10b need_render=true). "
                "Use --resume to render it, or repeat --rebuild --force "
                "to discard the completed analysis."
            ),
            "exit_code": 0,
        }

    receipts: list[str] = []
    _run_script(
        "check_state.py",
        [str(output_dir), "--auto-clean"],
        acceptable=(0,),
    )
    lock = _run_script(
        "acquire_lock.py",
        [str(output_dir / ".appsec-lock"), f"--run-id={cfg['run_id']}"],
        acceptable=(0,),
    )
    first_lock_line = (lock.stdout or "").strip().splitlines()
    receipts.append(first_lock_line[0] if first_lock_line else "lock acquired")

    try:
        # Every mutation below happens only after this invocation owns the
        # lock. This is stricter than the legacy prose order and prevents a
        # second invocation from quarantining or deleting an active run's
        # intermediates.
        _run_script(
            "validate_cache.py",
            [str(output_dir), "--quarantine"],
            acceptable=(0, 1, 2),
        )

        if cfg["mode"] == "full":
            _run_script(
                "snapshot_preserved_sections.py",
                [
                    str(output_dir),
                    "--plugin-root",
                    str(PLUGIN_ROOT),
                    "--repo-root",
                    str(repo_root),
                ],
                acceptable=(0, 1, 2),
            )
            removed = _cleanup_full(output_dir)
        else:
            removed = _cleanup_rebuild(output_dir)
            cfg["baseline_state"] = "empty"
        removed_preexisting = sum(item.rstrip("/") in existing_names for item in removed)
        receipts.append(f"{cfg['mode']} cleanup: {removed_preexisting} pre-existing item(s)")
        _append_event(
            output_dir,
            "PREFLIGHT_CLEANUP",
            (
                f"mode={cfg['mode']} "
                f"had_state={str(had_cleanup_state).lower()} "
                f"removed_preexisting={removed_preexisting}"
            ),
        )

        config_path = _persist_config(cfg, output_dir)
        _activate_markers(cfg)
        _run_script(
            "acquire_lock.py",
            [
                str(output_dir / ".appsec-lock"),
                f"--run-id={cfg['run_id']}",
                "--heartbeat",
                "--phase=skill",
                "--step=stage1-dispatch",
            ],
        )
        _prepasses(cfg, receipts)
        _fetch_requirements(cfg)
    except (ControllerError, OSError) as exc:
        try:
            (output_dir / ".appsec-lock").unlink()
        except OSError:
            pass
        _deactivate_markers()
        if isinstance(exc, ControllerError):
            raise
        raise ControllerError(f"preflight filesystem operation failed: {exc}") from exc

    _append_event(
        output_dir,
        "ORCHESTRATION_READY",
        f"mode={cfg['mode']} depth={cfg['assessment_depth']} runtime=thin-full",
    )
    # Detect the host session model (fail-safe: '' on any miss) so the Pre-flight
    # box can fold in the effective routing + cost advisory. resolve_config is
    # otherwise blind to the session; this is the thin-path injection point.
    try:
        session_model = detect_session_model.detect_session_model()
    except Exception:
        session_model = ""
    # Interactive orchestrator-model selection signal (computed BEFORE the box so
    # the box can suppress the now-redundant session advisories when the prompt
    # will fire). Needed when the session model is detected AND diverges from the
    # repo-size recommendation (covers BOTH a Sonnet-5 and an Opus session), and
    # the run is interactive (forced false under APPSEC_HEADLESS=1).
    _orch_rec = cfg.get("orchestrator_recommended_model", "")
    _headless = os.environ.get("APPSEC_HEADLESS", "").strip().lower() in ("1", "true", "yes", "on")
    _orch_prompt_needed = bool(
        session_model and _orch_rec and not resolve_config._same_model(session_model, _orch_rec) and not _headless
    )
    # When the interactive prompt will handle the model choice, drop the passive
    # session cost callout + orchestrator recommendation line from the box (they
    # would just repeat the prompt). Keep them when no prompt fires (headless /
    # matching / undetected) so that surface still carries the advisory.
    # Positional (not keyword) so existing render_run_plan spies in the tests that
    # take *args without **kwargs keep working.
    run_plan = resolve_config.render_run_plan(
        cfg,
        None,
        None,
        "equal",
        session_model,
        _orch_prompt_needed,
    )
    if cfg["mode"] == "rebuild":
        workspace_note = (
            f"removed {removed_preexisting} prior item(s); changelog audit archived when present"
            if had_cleanup_state
            else "clean slate; nothing pre-existing to discard"
        )
    else:
        workspace_note = (
            f"removed {removed_preexisting} stale intermediate item(s); prior deliverables and baseline preserved"
        )
    run_plan = run_plan.rstrip() + "\n\nWorkspace\n" + f"  Cleanup  : {workspace_note}\n"
    validator_advisory = _validator_advisory()
    if validator_advisory:
        run_plan += "\nValidator\n" + f"  Advisory : {validator_advisory}\n"
        _append_event(
            output_dir,
            "VALIDATOR_ADVISORY",
            validator_advisory,
            level="WARN",
        )
    context_advisory = _session_context_advisory(output_dir)
    if context_advisory:
        run_plan = run_plan.rstrip() + "\n\nSession context\n" + f"  Advisory : {context_advisory}\n"
        _append_event(
            output_dir,
            "SESSION_CONTEXT_ADVISORY",
            context_advisory,
            level="WARN",
        )
    estimate = _duration_estimate(cfg)
    return {
        "schema_version": 1,
        "action": "dispatch_agent",
        "mode": cfg["mode"],
        "stage": "stage1",
        "instruction_file": str(THIN_STAGE1_RUNTIME),
        "preflight_status": str(cfg.get("preflight_status") or ""),
        "run_plan": run_plan,
        "config_path": str(config_path),
        "dispatch_values": _dispatch_values(cfg, estimate),
        "session_model": session_model,
        "orchestrator_recommended_model": _orch_rec,
        "orchestrator_recommendation_reason": cfg.get("orchestrator_recommendation_reason", ""),
        "orchestrator_prompt_needed": _orch_prompt_needed,
        "receipts": receipts,
    }


def _best_effort_script(
    output_dir: Path,
    name: str,
    args: list[str],
    receipts: list[str],
) -> bool:
    try:
        _run_script(name, args)
        return True
    except ControllerError as exc:
        receipts.append(f"{name}: best-effort failure")
        _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")
        return False


def post_stage1(output_dir: Path) -> dict[str, Any]:
    """Run the deterministic thin-path gates after the Stage-1 agents return."""
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"
    required = (".recon-summary.md", ".threats-merged.json", ".triage-flags.json", "threat-model.yaml")
    missing = [name for name in required if not (output_dir / name).is_file()]
    if missing:
        raise ControllerError(f"Stage 1 did not produce required artifacts: {', '.join(missing)}")
    if not _checkpoint_needs_render(output_dir):
        raise ControllerError(
            "Stage 1 completion checkpoint is missing or invalid; expected phase=10b status=completed need_render=true"
        )

    _run_script("check_stride_dispatch.py", [str(output_dir)])
    if not _upgrade_bootstrap_yaml(output_dir, cfg):
        raise ControllerError("Stage 1 left a bootstrap threat-model.yaml that could not be upgraded")
    receipts: list[str] = []
    # Normalize cross-artifact invariants before the hard schema/cross-field
    # gate. In particular, invalid CVSS scope must be repaired before
    # validate_intermediate evaluates the eligibility rule; the reverse order
    # would block Stage 2 before the deterministic enforcer could run.
    _best_effort_script(output_dir, "enforce_yaml_invariants.py", [str(output_dir)], receipts)
    _run_script(
        "validate_intermediate.py",
        ["threat_model_output", str(output_dir / "threat-model.yaml")],
    )
    _best_effort_script(
        output_dir,
        "triage_compute_ranking.py",
        [str(output_dir), "--force"],
        receipts,
    )
    try:
        _run_external(
            [
                "bash",
                str(SCRIPT_DIR / "auto_emitter_pass.sh"),
                str(output_dir),
                str(cfg.get("repo_root") or output_dir),
                str(PLUGIN_ROOT),
                "false",
            ]
        )
    except ControllerError as exc:
        receipts.append("auto_emitter_pass.sh: best-effort failure")
        _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")

    _run_script("validate_mitigation_quality.py", [str(output_dir)])
    _run_script(
        "assert_completeness.py",
        [str(output_dir), "--phase", "build", "--plugin-root", str(PLUGIN_ROOT)],
    )
    _append_event(output_dir, "POST_STAGE1_GATES_PASSED", "thin deterministic Stage-1 gates passed")
    return {
        "schema_version": 1,
        "action": "run_gate",
        "mode": cfg["mode"],
        "stage": "stage1",
        "config_path": str(config_path),
        "receipts": ["Stage-1 artifacts and gates verified", *receipts],
    }


_ABUSE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def prepare_abuse(output_dir: Path) -> dict[str, Any]:
    """Match abuse cases and return a bounded verifier fan-out action."""
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"
    common = {
        "schema_version": 1,
        "mode": cfg["mode"],
        "stage": "stage1c",
        "config_path": str(config_path),
        "dispatch_values": _dispatch_values(cfg),
    }
    if cfg.get("skip_abuse_case_verification"):
        return {**common, "action": "run_gate", "receipts": ["Abuse verification disabled"]}

    repo_root = str(cfg.get("repo_root") or output_dir)
    args = [
        "match",
        "--output-dir",
        str(output_dir),
        "--repo-root",
        repo_root,
        "--signals",
        str(output_dir / ".recon-signals.json"),
    ]
    if org_profile := str(cfg.get("org_profile_path") or ""):
        args += ["--org-profile", org_profile]
    match = _run_script("match_abuse_cases.py", args, acceptable=(0, 1, 2))
    listed = _run_script(
        "match_abuse_cases.py",
        ["list-candidates", "--output-dir", str(output_dir)],
        acceptable=(0,),
    )
    candidates = [item for item in (listed.stdout or "").split() if _ABUSE_ID_RE.fullmatch(item)]
    if len(candidates) > 64:
        raise ControllerError(f"abuse verifier fan-out has {len(candidates)} candidates; maximum is 64")
    receipts = [f"abuse candidates: {len(candidates)}"]
    if match.returncode != 0:
        receipts.append(f"matcher returned {match.returncode}; partial candidates retained")
    if not candidates or (output_dir / ".budget-critical").exists():
        return {**common, "action": "run_gate", "candidates": candidates, "receipts": receipts}
    return {
        **common,
        "action": "dispatch_parallel",
        "instruction_file": str(THIN_STAGE1C_RUNTIME),
        "candidates": candidates,
        "receipts": receipts,
    }


def finalize_abuse(output_dir: Path) -> dict[str, Any]:
    """Merge verifier sidecars and materialize the final abuse-case artifacts."""
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"
    receipts: list[str] = []
    for name, args in (
        ("verify_abuse_cases.py", ["merge", "--output-dir", str(output_dir)]),
        ("match_abuse_cases.py", ["finalize", "--output-dir", str(output_dir)]),
        ("promote_verified_abuse_cases.py", ["--output-dir", str(output_dir)]),
    ):
        _best_effort_script(output_dir, name, args, receipts)

    verdicts = output_dir / ".abuse-case-verdicts.json"
    if verdicts.is_file():
        _best_effort_script(
            output_dir,
            "build_threat_model_yaml.py",
            [
                str(output_dir),
                "--repo-root",
                str(cfg.get("repo_root") or output_dir),
                "--plugin-root",
                str(PLUGIN_ROOT),
            ],
            receipts,
        )
    _run_script("abuse_case_gate.py", ["--output-dir", str(output_dir)])
    if verdicts.is_file():
        _best_effort_script(
            output_dir,
            "triage_compute_ranking.py",
            [str(output_dir), "--if-deterministic-owner"],
            receipts,
        )
    render_args = [
        "--output-dir",
        str(output_dir),
        "--repo-root",
        str(cfg.get("repo_root") or output_dir),
    ]
    if org_profile := str(cfg.get("org_profile_path") or ""):
        render_args += ["--org-profile", org_profile]
    _best_effort_script(output_dir, "render_abuse_cases.py", render_args, receipts)
    _append_event(output_dir, "ABUSE_FINALIZE_COMPLETE", "thin abuse-case finalization complete")
    return {
        "schema_version": 1,
        "action": "run_gate",
        "mode": cfg["mode"],
        "stage": "stage1c",
        "config_path": str(config_path),
        "receipts": ["Abuse-case artifacts finalized", *receipts],
    }


def prepare_stage2(output_dir: Path) -> dict[str, Any]:
    """Prepare structural fragments and select the compact Stage-2 dispatch."""
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"
    receipts: list[str] = []
    _best_effort_script(
        output_dir,
        "pregenerate_fragments.py",
        [
            str(output_dir),
            "--force",
            "--only",
            "system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md",
        ],
        receipts,
    )
    for only in ("security-architecture.md", "ms-critical-attack-tree.json"):
        _best_effort_script(
            output_dir,
            "pregenerate_fragments.py",
            [str(output_dir), "--only", only],
            receipts,
        )
    _best_effort_script(
        output_dir,
        "restore_preserved_sections.py",
        [
            str(output_dir),
            "--current-depth",
            str(cfg.get("assessment_depth") or "standard"),
            "--plugin-root",
            str(PLUGIN_ROOT),
            "--repo-root",
            str(cfg.get("repo_root") or output_dir),
        ],
        receipts,
    )
    for name in (".budget-critical", ".budget-warning"):
        path = output_dir / name
        try:
            if path.is_file() or path.is_symlink():
                path.unlink()
        except OSError:
            pass

    retry_pending = (output_dir / ".inline-shortcut-retry-count").is_file()
    parallel = (
        bool(cfg.get("enrich_arch_fragments")) and os.environ.get("APPSEC_PARALLEL_RENDER") != "0" and not retry_pending
    )
    action = "dispatch_parallel" if parallel else "dispatch_agent"
    if parallel:
        _best_effort_script(
            output_dir,
            "log_event.py",
            [
                str(output_dir),
                "phase-start",
                "[Phase 11/11] Finalization (parallel renderer)",
                "--agent",
                "threat-renderer",
            ],
            receipts,
        )
    _append_event(output_dir, "STAGE2_READY", f"parallel={str(parallel).lower()}")
    return {
        "schema_version": 1,
        "action": action,
        "mode": cfg["mode"],
        "stage": "stage2",
        "instruction_file": str(THIN_STAGE2_RUNTIME),
        "config_path": str(config_path),
        "dispatch_values": _dispatch_values(cfg),
        "receipts": [f"Stage-2 structural fragments prepared; parallel={str(parallel).lower()}", *receipts],
    }


# LLM-authored render fragments a Stage-2 renderer must produce before the
# report can be composed. Their presence means the expensive rendering already
# happened and only the deterministic compose remains.
_REQUIRED_RENDER_FRAGMENTS = ("ms-verdict.json", "security-architecture.md")


def _upgrade_bootstrap_yaml(output_dir: Path, cfg: dict[str, Any]) -> bool:
    """Rebuild a ``_bootstrap`` stub ``threat-model.yaml`` into the canonical one.

    ``triage_compute_ranking.py --bootstrap-yaml`` writes a minimal stub
    (``meta._bootstrap: true`` — threats only, no attack surface, trust
    boundaries or security controls) so a Phase-11 cut-off still leaves *a* yaml
    on disk. Every gate in ``next`` only tested that the file EXISTS, so the stub
    sailed through as if it were canonical: the 2026-07-19 insecure-python-app
    run lost Analyst-B to a session limit, kept a stub carrying 46 threats and 0
    attack-surface entries, and the finalize gate still answered ``stage3``.

    ``build_threat_model_yaml.py`` already recognises the stub and rebuilds it
    from the Stage-1 intermediates, so this recovery is deterministic and needs
    no agent — the same shape as ``_compose_if_ready`` for the report itself.

    Returns True when the yaml is (or has become) canonical, False when the stub
    could not be upgraded so the caller can fall back to a Stage-1 dispatch.
    Fail-safe: never raises into ``next``'s JSON output.
    """
    yaml_path = output_dir / "threat-model.yaml"

    def _is_bootstrap() -> bool | None:
        """True/False, or None when the yaml cannot be read or parsed."""
        try:
            import yaml  # local import: a missing dep must not break `next`

            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        except Exception:
            return None
        return bool((data.get("meta") or {}).get("_bootstrap"))

    state = _is_bootstrap()
    if state is not True:
        # Canonical, or unreadable — an unparseable yaml is a different failure
        # that the existing downstream gates own. Only the stub is ours.
        return True

    args = [str(output_dir)]
    if repo_root := str(cfg.get("repo_root") or ""):
        args += ["--repo-root", repo_root]
    args += ["--plugin-root", str(SCRIPT_DIR.parent)]
    try:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "build_threat_model_yaml.py"), *args],
            cwd=str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0:
        return False
    return _is_bootstrap() is False


def _compose_if_ready(output_dir: Path, repo_root: str) -> bool:
    """Deterministically compose or refresh ``threat-model.md`` from fragments.

    Closes the thin-runtime gap where the orchestrator authored the render
    fragments but ended — turn budget, or a skipped skill-level step — before
    issuing ``compose_threat_model.py``, leaving ``threat-model.yaml`` plus a
    full ``.fragments/`` set but no report (2026-07-02 juice-shop thin run).

    Also refreshes a stale report when the checkpoint says Stage 1 still needs
    rendering. Only fires when the LLM-authored fragments are already present,
    so no agent work is needed; otherwise returns False and the caller falls
    back to a Stage-2 agent dispatch. Runs the canonical finalization tail
    (compose --strict → apply_prose_fixes → qa_checks autofix). Fail-safe: any
    error returns False and never raises into ``next``'s JSON output.
    """
    frag_dir = output_dir / ".fragments"
    if not all((frag_dir / name).is_file() for name in _REQUIRED_RENDER_FRAGMENTS):
        return False
    md = output_dir / "threat-model.md"

    def _run(*cmd: str) -> bool:
        try:
            proc = subprocess.run(
                [sys.executable, *cmd],
                cwd=str(SCRIPT_DIR),
                capture_output=True,
                text=True,
                timeout=600,
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    # Complete the canonical mitigation cards before any fragment or report is
    # rendered. The normal skill path already ran these idempotent helpers; the
    # thin-runtime recovery path can reach this point after a turn cut-off, so
    # it must not bypass the developer-actionability contract.
    if not _run(str(SCRIPT_DIR / "emit_general_mitigation_titles.py"), str(output_dir)):
        return False
    # Scanner findings carry only a one-line mitigation_title; synthesise a
    # structured remediation block (steps + verification) from the check library
    # before hydration so the P1/P2 quality gate is satisfiable on the recovery
    # path too (mirrors the auto-emitter pass ordering).
    if not _run(str(SCRIPT_DIR / "backfill_scanner_remediation.py"), str(output_dir)):
        return False
    if not _run(str(SCRIPT_DIR / "hydrate_mitigation_details.py"), str(output_dir)):
        return False
    if not _run(str(SCRIPT_DIR / "validate_mitigation_quality.py"), str(output_dir)):
        return False

    # Mechanical structural fragments (idempotent backstop), then the strict
    # compose, then the prose-fix + autofix tail (AGENTS.md "Critical ordering").
    _run(
        str(SCRIPT_DIR / "pregenerate_fragments.py"),
        str(output_dir),
        "--force",
        "--only",
        "system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md",
    )
    # Conditional MS fragments (idempotent, self-gating — a renderer-authored
    # copy already on disk is preserved). ms-ai-exposure.json is the recurring
    # gap: the thin renderer often skips it, so the "AI / LLM Exposure" MS
    # callout silently vanishes even though the yaml carries an LLM surface
    # (2026-07-02). Deriving it here from the yaml guarantees the section.
    _run(
        str(SCRIPT_DIR / "pregenerate_fragments.py"),
        str(output_dir),
        "--only",
        "ms-ai-exposure.json,ms-critical-attack-tree.json",
    )
    if not _run(str(SCRIPT_DIR / "compose_threat_model.py"), "--output-dir", str(output_dir), "--strict"):
        return False
    if not md.is_file():
        return False
    _run(str(SCRIPT_DIR / "apply_prose_fixes.py"), str(md))
    _run(str(SCRIPT_DIR / "qa_checks.py"), "autofix", str(md), repo_root or str(output_dir))
    try:
        (output_dir / ".appsec-checkpoint").write_text(
            f"phase=11 status=completed timestamp={datetime.now(timezone.utc).isoformat()}\n",
            encoding="utf-8",
        )
        _append_event(output_dir, "PHASE_END", "[Phase 11/11] Finalization (controller compose)")
    except OSError:
        return False
    return md.is_file()


def _stamp_if_configured(output_dir: Path, cfg: dict[str, Any]) -> None:
    """Deterministically produce the slug-stamped deliverable copy set.

    ``--slug`` asks for a postfix-stamped, collision-proof copy of the
    deliverables (``threat-model-<slug>.md`` / ``.yaml`` / ``.figure*.svg`` …).
    In the skill body that stamp is the very last, LLM-driven Bash block and it
    guards on an in-memory ``$SLUG`` shell variable — neither the variable nor
    the "run this trailing step" intent survives a context compaction, so a
    resumed run silently shipped the canonical files with no stamped set
    (2026-07-15 juice-shop). Anchoring the stamp here, in the mandatory
    re-entrant ``next`` gate that reads the durable on-disk config, makes it
    deterministic: any run that reaches ``action=complete`` gets the stamped
    copies regardless of compaction. Idempotent (re-stamps only when the
    canonical report is newer than the stamped copy) and fail-safe (never
    raises into ``next``'s JSON output). This gate fires before the skill's
    post-summary cleanup, so ``.skill-config.json`` is still on disk; PDF/HTML
    exported by the skill after this gate remain the trailing block's job.
    """
    slug = str(cfg.get("slug") or "").strip()
    if not slug:
        return
    md = output_dir / "threat-model.md"
    if not md.is_file():
        return
    stamped = output_dir / f"threat-model-{slug}.md"
    try:
        if stamped.is_file() and stamped.stat().st_mtime >= md.stat().st_mtime:
            return  # already stamped from the current report — nothing to do
    except OSError:
        pass
    try:
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "stamp_threat_model.py"),
                "--output-dir",
                str(output_dir),
                "--slug",
                slug,
            ],
            cwd=str(SCRIPT_DIR),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def next_action(output_dir: Path) -> dict[str, Any]:
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"

    common = {
        "schema_version": 1,
        "mode": cfg["mode"],
        "config_path": str(config_path),
        "dispatch_values": _dispatch_values(cfg),
    }
    if not (output_dir / "threat-model.yaml").is_file():
        return {
            **common,
            "action": "dispatch_agent",
            "stage": "stage1",
            "instruction_file": str(THIN_STAGE1_RUNTIME),
        }
    # A bootstrap stub IS a file but is not a model — upgrade it deterministically
    # before anything downstream treats it as canonical. Unrecoverable ⇒ Stage 1.
    if not _upgrade_bootstrap_yaml(output_dir, cfg):
        return {
            **common,
            "action": "dispatch_agent",
            "stage": "stage1",
            "instruction_file": str(THIN_STAGE1_RUNTIME),
        }
    if not (output_dir / "threat-model.md").is_file() or _checkpoint_needs_render(output_dir):
        # Deterministic compose backstop: when the render fragments are already
        # on disk the remaining work is a pure compose, so finish it here rather
        # than re-dispatching the (expensive) renderer. Only falls through to a
        # Stage-2 agent when the fragments are genuinely missing.
        if not _compose_if_ready(output_dir, str(cfg.get("repo_root") or "")):
            retry_path = output_dir / ".inline-shortcut-retry-count"
            try:
                retry_count = int(retry_path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                retry_count = 0
            if retry_count >= 2:
                raise ControllerError(
                    "Stage 2 could not produce the required render fragments after two retries; "
                    f"inspect {output_dir / '.fragments'} and {output_dir / '.agent-run.log'}"
                )
            retry_count += 1
            try:
                retry_path.write_text(f"{retry_count}\n", encoding="utf-8")
            except OSError as exc:
                raise ControllerError(f"cannot persist Stage-2 retry counter: {exc}") from exc
            return {
                **common,
                "action": "dispatch_agent",
                "stage": "stage2",
                "instruction_file": str(THIN_STAGE2_RUNTIME),
                "receipts": [f"Stage-2 render fragments incomplete; retry {retry_count}/2"],
            }
    for name in (".inline-shortcut-retry-count", ".inline-shortcut-repair-plan.json"):
        try:
            (output_dir / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
    if not cfg.get("skip_qa") and not (output_dir / ".qa-status.json").is_file():
        return {
            **common,
            "action": "dispatch_agent",
            "stage": "stage3",
            "instruction_file": str(LEGACY_RUNTIME),
        }
    if cfg.get("architect_review") and not (output_dir / ".architect-status.json").is_file():
        return {
            **common,
            "action": "dispatch_agent",
            "stage": "stage4",
            "instruction_file": str(LEGACY_RUNTIME),
        }
    # Deterministic slug-stamp backstop: the run is complete, so emit the
    # postfix-stamped deliverable copy set here rather than relying on the
    # trailing LLM-driven skill block (which a compaction-resumed orchestrator
    # can skip, and whose $SLUG guard does not survive compaction anyway).
    _stamp_if_configured(output_dir, cfg)
    return {
        **common,
        "action": "complete",
        "stage": "complete",
    }


def _split_remainder(values: list[str]) -> list[str]:
    return values[1:] if values and values[0] == "--" else values


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    route_parser = sub.add_parser("route")
    route_parser.add_argument("arguments", nargs=argparse.REMAINDER)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--force", action="store_true")
    prepare_parser.add_argument("arguments", nargs=argparse.REMAINDER)
    post_stage1_parser = sub.add_parser("post-stage1")
    post_stage1_parser.add_argument("--output-dir", required=True)
    prepare_abuse_parser = sub.add_parser("prepare-abuse")
    prepare_abuse_parser.add_argument("--output-dir", required=True)
    finalize_abuse_parser = sub.add_parser("finalize-abuse")
    finalize_abuse_parser.add_argument("--output-dir", required=True)
    prepare_stage2_parser = sub.add_parser("prepare-stage2")
    prepare_stage2_parser.add_argument("--output-dir", required=True)
    next_parser = sub.add_parser("next")
    next_parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "route":
            action = route(_split_remainder(args.arguments))
        elif args.command == "prepare":
            action = prepare(
                _split_remainder(args.arguments),
                force=args.force,
            )
        elif args.command == "post-stage1":
            action = post_stage1(Path(args.output_dir))
        elif args.command == "prepare-abuse":
            action = prepare_abuse(Path(args.output_dir))
        elif args.command == "finalize-abuse":
            action = finalize_abuse(Path(args.output_dir))
        elif args.command == "prepare-stage2":
            action = prepare_stage2(Path(args.output_dir))
        else:
            action = next_action(Path(args.output_dir))
    except (ControllerError, SystemExit, OSError) as exc:
        code = exc.exit_code if isinstance(exc, ControllerError) else 2
        action = {
            "schema_version": 1,
            "action": "abort",
            "reason": str(exc),
            "exit_code": code,
        }
    return _emit(action)


if __name__ == "__main__":
    raise SystemExit(main())
