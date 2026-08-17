#!/usr/bin/env python3
"""Deterministic control-plane helpers for the threat-model skill.

The controller owns full/rebuild preflight state mutations and emits a compact,
schema-validated action.  It never invokes Claude Agent/Task tools; the thin
skill runtime remains responsible for those calls.

Commands:

    orchestration_controller.py route -- <create-threat-model arguments>
    orchestration_controller.py prepare [--force] -- <arguments>
    orchestration_controller.py post-stage1a --output-dir <path>
    orchestration_controller.py finalize-stage1b --output-dir <path>
    orchestration_controller.py post-stage1c --output-dir <path>
    orchestration_controller.py prepare-abuse --output-dir <path>
    orchestration_controller.py finalize-abuse --output-dir <path>
    orchestration_controller.py prepare-stage2 --output-dir <path>
    orchestration_controller.py context-v2-prepare-stride --output-dir <path>
    orchestration_controller.py context-v2-post-stride --output-dir <path>
    orchestration_controller.py context-v2-post-merge --output-dir <path>
    orchestration_controller.py context-v2-post-evidence --output-dir <path>
    orchestration_controller.py context-v2-post-triage --output-dir <path>
    orchestration_controller.py context-v2-finalize --output-dir <path>
    orchestration_controller.py verify-receipts --output-dir <path> --receipt <path> <sha256> [...]
    orchestration_controller.py next --output-dir <path>
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path
from typing import Any

import yaml

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:  # pragma: no cover - exercised through the fail-closed guard
    Draft202012Validator = None  # type: ignore[assignment,misc]
    Registry = None  # type: ignore[assignment,misc]
    Resource = None  # type: ignore[assignment,misc]

SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

import budget_watchdog  # noqa: E402
import check_permissions  # noqa: E402
import context_routing  # noqa: E402
import cutoff_cause  # noqa: E402
import detect_session_model  # noqa: E402
import ensure_output_gitignore  # noqa: E402
import merge_threats as merge_decision_contract  # noqa: E402
import resolve_config  # noqa: E402
import stride_dispatch_waves  # noqa: E402
import telemetry_consistency  # noqa: E402
import validate_intermediate as intermediate_contract  # noqa: E402
import validate_recon_summary as recon_summary_contract  # noqa: E402
import validate_threat_modeling_context as context_document_contract  # noqa: E402
from event_log import format_line  # noqa: E402

ACTION_SCHEMA = PLUGIN_ROOT / "schemas" / "orchestration-action.schema.json"
THIN_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md"
THIN_RERENDER_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md"
THIN_STAGE1_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1.md"
THIN_STAGE1_V2_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md"
THIN_STAGE1B_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1b.md"
THIN_STAGE1D_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1d.md"
THIN_STAGE2_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage2.md"
LEGACY_RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
CONTEXT_V2_GENERATION = "context-v2"
LEGACY_GENERATION = "legacy"

MAX_ACTION_BYTES = 65_536
MAX_STRIDE_ANALYST_CONTEXT_BYTES = 1_048_576
MAX_RECON_SIGNALS_BYTES = 1_048_576
TARGET_RECON_SUMMARY_LINES = 200
MAX_THREAT_MODELING_CONTEXT_BYTES = context_document_contract.MAX_BYTES
MAX_ORG_CONTEXT_BYTES = 262_144
_RECEIPT_RECORD_KEYS = {
    "schemas/trust-boundary-assessment-input.schema.json#v1": "components",
    "schemas/fragments/trust-boundaries.schema.json#v2": "trust_boundaries",
    "schemas/stride-evidence-bundle.schema.json#v1": "source_slices",
    "schemas/stride-component-context-plan.schema.json#v1": "inputs",
    "schemas/stride-component-repository-roots.schema.json#v1": "repositories",
    "schemas/stride-component-architecture-context.schema.json#v1": "attributes",
    "schemas/stride-component-business-context.schema.json#v1": "attributes",
    "schemas/stride-run-llm-policy.schema.json#v1": "attributes",
    "schemas/stride-component-security-context.schema.json#v1": "records",
    "schemas/stride-dispatch-manifest.schema.yaml#v2": "components",
    "schemas/stride-repository-registry.schema.json#v1": "repositories",
    "schemas/threats-merged.schema.yaml#v1": "threats",
    "schemas/triage-flags.schema.yaml#v2": "flags",
    "schemas/fragments/mitigation-overrides.schema.json#v1": "splits",
    "schemas/fragments/tier-root-causes.schema.json#v1": "tier_root_causes",
    "schemas/merge-candidates.schema.json#v1": "candidate_groups",
    "schemas/merge-review-context.schema.json#v1": "candidate_groups",
    "schemas/merge-decisions.schema.json#v2": "decisions",
    "schemas/route-inventory.schema.json#v1": "routes",
    "schemas/recon-patterns.schema.json#v1": "categories",
    "schemas/recon-summary-context.schema.json#v1": "sections",
    "schemas/architecture-route-context.schema.json#v1": "routes",
    "schemas/recon-signals.schema.json#v2": "signals",
    "schemas/evidence-verifier-context.schema.json#v1": "samples",
    "schemas/post-stride-generated-threats.schema.json#v1": "threats",
    "schemas/post-stride-proposed-mitigations.schema.json#v1": "mitigations",
    "schemas/abuse-case-verifier-context.schema.json#v1": "candidate",
    "schemas/actors-merged-static.schema.yaml#v1": "resolved_actors",
    "schemas/actors-resolved.schema.yaml#v1": "resolved_actors",
}
_OPTIONAL_RECEIPT_RECORD_KEYS = {
    "schemas/fragments/mitigation-overrides.schema.json#v1",
}
SEMANTIC_ROLE_REGISTRY: dict[str, dict[str, Any]] = {
    "abuse_case_verifier": {
        "agent": "appsec-abuse-case-verifier",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-abuse-case-verifier.md",
        "tools": ("Read", "Grep", "Bash", "Write"),
        "output_contracts": ("schemas/fragments/verdict.schema.json",),
    },
    "actor_discoverer": {
        "agent": "appsec-actor-discoverer",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-actor-discoverer.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": ("schemas/actors-discovered.schema.yaml",),
    },
    "architecture_analyst": {
        "agent": "appsec-architecture-analyst",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-architecture-analyst.md",
        "tools": ("Read", "Grep", "Bash", "Write"),
        "output_contracts": (
            "schemas/fragments/components.schema.json",
            "schemas/fragments/data-flows.schema.json",
            "schemas/fragments/assets.schema.json",
            "schemas/fragments/attack-surface-overrides.schema.json",
        ),
    },
    "config_scanner": {
        "agent": "appsec-config-scanner",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-config-scanner.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": ("schemas/config-scan-findings.schema.yaml",),
    },
    "context_resolver": {
        "agent": "appsec-context-resolver",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-context-resolver.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": ("contract:threat-modeling-context-markdown-v1",),
    },
    "control_analyst": {
        "agent": "appsec-control-analyst",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-control-analyst.md",
        "tools": ("Read", "Grep", "Bash", "Write"),
        "output_contracts": (
            "schemas/fragments/security-controls.schema.json",
            "schemas/stride-analyst-context.schema.json",
        ),
    },
    "evidence_verifier": {
        "agent": "appsec-evidence-verifier",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-evidence-verifier.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": ("schemas/evidence-verification.schema.json",),
    },
    "post_stride_synthesizer": {
        "agent": "appsec-post-stride-synthesizer",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-post-stride-synthesizer.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": (
            "schemas/fragments/mitigation-overrides.schema.json",
            "schemas/fragments/tier-root-causes.schema.json",
        ),
    },
    "recon_scanner": {
        "agent": "appsec-recon-scanner",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-recon-scanner.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": (
            "contract:recon-summary-markdown-v1",
            "schemas/recon-signals.schema.json",
        ),
    },
    "stride_analyzer": {
        "agent": "appsec-stride-analyzer-v2",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-stride-analyzer-v2.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": ("schemas/stride.schema.yaml",),
    },
    "threat_merger": {
        "agent": "appsec-threat-merger",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-threat-merger.md",
        "tools": ("Read", "Bash", "Write"),
        "output_contracts": ("schemas/merge-decisions.schema.json",),
    },
    "triage_validator": {
        "agent": "appsec-triage-validator",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-triage-validator.md",
        "tools": ("Read", "Glob", "Grep", "Bash", "Write"),
        "output_contracts": (
            "schemas/triage-flags.schema.yaml",
            "schemas/threats-merged.schema.yaml",
        ),
    },
    "trust_boundary_analyst": {
        "agent": "appsec-trust-boundary-analyst",
        "instruction": PLUGIN_ROOT / "agents" / "appsec-trust-boundary-analyst.md",
        "tools": ("Read", "Grep", "Write", "Bash"),
        "output_contracts": ("schemas/fragments/trust-boundary-candidates.schema.json",),
    },
}

SEMANTIC_ROLE_MODEL_KEYS = {
    "abuse_case_verifier": "abuse_verifier_model",
    "actor_discoverer": "actor_discovery_model",
    "architecture_analyst": "orchestrator_model",
    "config_scanner": "config_scanner_model",
    "context_resolver": "context_resolver_model",
    "control_analyst": "orchestrator_model",
    "evidence_verifier": "evidence_verifier_model",
    "post_stride_synthesizer": "triage_model",
    "recon_scanner": "recon_scanner_model",
    "stride_analyzer": "stride_model",
    "threat_merger": "merger_model",
    "triage_validator": "triage_model",
    "trust_boundary_analyst": "orchestrator_model",
}

# Every context-v2 LLM artifact is contract-gated before the next terminal
# boundary. Producer-gated roles run the shared validator within their own
# budget, so they can correct a bad write without restarting Stage 1. STRIDE
# is the deliberate exception: its controller-owned bounded retry consumes the
# same validator errors and redispatches only the affected component.
CONTEXT_V2_PRODUCER_GATED_ROLES = frozenset(
    {
        "abuse_case_verifier",
        "actor_discoverer",
        "architecture_analyst",
        "config_scanner",
        "context_resolver",
        "control_analyst",
        "evidence_verifier",
        "post_stride_synthesizer",
        "recon_scanner",
        "threat_merger",
        "triage_validator",
        "trust_boundary_analyst",
    }
)
CONTEXT_V2_CONTROLLER_RECOVERY_ROLES = frozenset({"stride_analyzer"})

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
    ".context-routing-plan.json",
    ".context-routing-plan.receipt.json",
    ".budget-critical",
    ".budget-warning",
    ".trust-boundary-assessment-input.json",
    ".trust-boundary-candidates.json",
}
_FULL_INTERMEDIATE_GLOBS = (".stride-*.json", ".merge-*.json")

_REBUILD_NAMES = {
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "threat-model.threatdragon.json",
    "threat-model.pdf",
    "threat-model.html",
    "pentest-tasks.yaml",
    ".architect-review.md",
    ".threat-modeling-context.md",
    ".business-context-input.md",
    ".recon-summary.md",
    ".recon-signals.json",
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
    ".recon-patterns.json",
    ".compose-stats.json",
    ".context-resolver.stdout",
    ".ctx-resolver.pid",
    ".recon-scanner.pid",
    ".recon-scanner.stdout",
    ".coverage-gaps.json",
    ".dispatch-waves.json",
    ".context-routing-plan.json",
    ".context-routing-plan.receipt.json",
    ".scan-manifest.txt",
    ".requirements.yaml",
    ".prior-findings-index.json",
    ".stage1-resume-count",
    ".triage-ranking.json",
    ".run-issues.json",
    ".run-issues-fixes.json",
    ".budget-critical",
    ".budget-warning",
    ".component-inventory-finalization.json",
    ".data-flows.json",
    ".trust-boundary-assessment-input.json",
    ".trust-boundary-candidates.json",
    ".trust-boundary-coverage.json",
    ".trust-boundary-diagnostics.json",
    ".trust-boundaries.json",
}
_REBUILD_GLOBS = (
    "threat-model.figure*.svg",
    "threat-model-*.md",
    "threat-model-*.yaml",
    "threat-model-*.sarif.json",
    "threat-model-*.threatdragon.json",
    "threat-model-*.pdf",
    "threat-model-*.html",
    "threat-model-*.figure*.svg",
    "pentest-tasks-*.yaml",
    ".stride-*.json",
    ".merge-*.json",
)
_REBUILD_DIRS = (
    ".fragments",
    ".appsec-cache",
    ".progress",
    ".taxonomy-slices",
    ".dispatch-context",
    ".merge-context",
)
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
    "write_threatdragon",
    "check_requirements",
    "requirements_url_override",
    "business_context_source",
    "skip_business_context",
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


class ProducerContractError(ControllerError):
    """An LLM-written artifact violates its contract.

    Distinct from every other gate failure because it is the one class a
    redispatch can fix: the producer wrote the wrong shape, the errors name
    exactly what is wrong, and nothing upstream is broken. Deterministic
    producers never raise it — a script that writes an invalid artifact is a
    defect, and repeating it would only hide that.
    """

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(message)
        self.errors = errors or [message]


#: One retry per producer artifact. A second identical failure is no longer
#: variance, and a run must not spend its budget rediscovering that.
MAX_PRODUCER_RETRIES = 1
PRODUCER_RETRY_LEDGER = ".producer-retries.json"
PRODUCER_REPAIR_DIR = ".producer-repair"


def _claim_producer_retry(output_dir: Path, key: str) -> int | None:
    """Return the attempt number for a retry, or None when the budget is spent.

    The ledger is persisted because each boundary command is its own process:
    without it every invocation would believe it holds the first retry.
    """
    path = output_dir / PRODUCER_RETRY_LEDGER
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(ledger, dict):
            ledger = {}
    except (OSError, ValueError):
        ledger = {}
    spent = ledger.get(key)
    spent = spent if isinstance(spent, int) and spent >= 0 else 0
    if spent >= MAX_PRODUCER_RETRIES:
        return None
    from _atomic_io import atomic_write_json  # noqa: PLC0415

    ledger[key] = spent + 1
    atomic_write_json(path, ledger, sort_keys=True)
    return spent + 2


def _write_producer_repair_brief(output_dir: Path, artifact: str, errors: list[str]) -> str:
    """Persist the validator errors the retry has to fix, and name its path."""
    from _atomic_io import atomic_write_json  # noqa: PLC0415

    name = f"{PRODUCER_REPAIR_DIR}/{artifact.lstrip('.')}"
    (output_dir / PRODUCER_REPAIR_DIR).mkdir(exist_ok=True)
    atomic_write_json(
        output_dir / name,
        {
            "schema_version": 1,
            "artifact": artifact,
            "errors": errors[:32],
            "instruction": (
                "Your previous write of this artifact was rejected. Fix exactly these "
                "contract violations and write the artifact again. Do not invent evidence "
                "to satisfy a rule; where no observation supports a value, choose the "
                "value the contract allows for an unobserved case."
            ),
        },
        sort_keys=True,
    )
    return name


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ControllerError(f"internal action manifest is not canonical JSON: {exc}") from exc


def _plugin_owned_instruction_paths() -> frozenset[Path]:
    paths = {
        THIN_RUNTIME,
        THIN_RERENDER_RUNTIME,
        THIN_STAGE1_RUNTIME,
        THIN_STAGE1_V2_RUNTIME,
        THIN_STAGE1B_RUNTIME,
        THIN_STAGE1D_RUNTIME,
        THIN_STAGE2_RUNTIME,
        LEGACY_RUNTIME,
    }
    paths.update(record["instruction"] for record in SEMANTIC_ROLE_REGISTRY.values())
    return frozenset(path.resolve() for path in paths)


def _canonical_output_root(action: dict[str, Any]) -> Path | None:
    artifact_paths = [
        path
        for job in action.get("dispatch_jobs", [])
        for key in ("input_artifacts", "output_artifacts")
        for path in job.get(key, [])
    ]
    artifact_paths.extend(receipt.get("artifact_path") for receipt in action.get("artifact_receipts", []))
    artifact_paths = [path for path in artifact_paths if isinstance(path, str)]
    if not artifact_paths:
        return None
    output_dir = action.get("dispatch_values", {}).get("output_dir")
    if not isinstance(output_dir, str) or not output_dir:
        raise ControllerError("internal action manifest with artifact paths requires dispatch_values.output_dir")
    return Path(output_dir).resolve()


def _resolve_artifact_path(output_root: Path, artifact_path: str) -> Path:
    relative = Path(artifact_path)
    if (
        not artifact_path
        or "\\" in artifact_path
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ControllerError(f"unsafe artifact path: {artifact_path!r}")
    resolved = (output_root / relative).resolve()
    try:
        resolved.relative_to(output_root)
    except ValueError as exc:
        raise ControllerError(f"artifact path escapes output directory: {artifact_path!r}") from exc
    return resolved


def _prepare_context_v2_dispatch_outputs(output_root: Path, jobs: list[dict[str, Any]]) -> None:
    """Remove prior bytes for outputs that the next semantic boundary must write.

    A schema-valid artifact from an older full run must never satisfy the next
    boundary when its current producer returned without writing. In-place
    repair outputs are preserved only when the same action also names them as
    inputs; their successor gate remains responsible for semantic validation.
    """
    output_root = output_root.resolve()
    protected = {
        artifact_path
        for job in jobs
        for artifact_path in job.get("input_artifacts", [])
        if isinstance(artifact_path, str)
    }
    removed: list[str] = []
    for artifact_path in {path for job in jobs for path in job.get("output_artifacts", []) if isinstance(path, str)}:
        if artifact_path in protected:
            continue
        _resolve_artifact_path(output_root, artifact_path)
        lexical_path = output_root / Path(artifact_path)
        if not lexical_path.exists() and not lexical_path.is_symlink():
            continue
        if lexical_path.is_dir() and not lexical_path.is_symlink():
            raise ControllerError(f"dispatch output artifact is a directory: {artifact_path!r}")
        try:
            lexical_path.unlink()
        except OSError as exc:
            raise ControllerError(f"cannot clear prior dispatch output {artifact_path!r}: {exc}") from exc
        removed.append(artifact_path)
    if removed:
        _append_event(
            output_root,
            "CONTEXT_V2_STALE_OUTPUTS_CLEARED",
            "removed=" + ",".join(sorted(removed)),
        )


def _validate_action_semantics(action: dict[str, Any]) -> None:
    if action.get("context_plan") is not None and action.get("action") not in {
        "dispatch_agent",
        "dispatch_parallel",
    }:
        raise ControllerError("effective-plan references are valid only on dispatch actions")
    instruction_file = action.get("instruction_file")
    if instruction_file is not None:
        if not isinstance(instruction_file, str):
            raise ControllerError("internal action instruction_file must be a string")
        instruction = Path(instruction_file)
        if not instruction.is_absolute() or instruction.resolve() not in _plugin_owned_instruction_paths():
            raise ControllerError("internal action instruction_file is not plugin-owned")

    semantic_role = action.get("semantic_role")
    if semantic_role is not None and semantic_role not in SEMANTIC_ROLE_REGISTRY:
        raise ControllerError(f"unknown semantic role: {semantic_role!r}")

    job_ids: set[str] = set()
    component_ids: set[str] = set()
    output_owners: dict[str, str] = {}
    all_inputs: set[str] = set()
    for job in action.get("dispatch_jobs", []):
        job_id = job["job_id"]
        if job_id in job_ids:
            raise ControllerError(f"duplicate dispatch job id: {job_id}")
        job_ids.add(job_id)
        component_id = job.get("component_id")
        if component_id is not None:
            if component_id in component_ids:
                raise ControllerError(f"duplicate dispatch component id: {component_id}")
            component_ids.add(component_id)
        role = job["semantic_role"]
        if role not in SEMANTIC_ROLE_REGISTRY:
            raise ControllerError(f"unknown semantic role: {role!r}")
        if semantic_role is not None and role != semantic_role:
            raise ControllerError("action semantic role does not match its dispatch job role")
        agent_type = job.get("agent_type")
        expected_agent = f"appsec-advisor:{SEMANTIC_ROLE_REGISTRY[role]['agent']}"
        if agent_type is not None and agent_type != expected_agent:
            raise ControllerError(f"dispatch agent type does not match semantic role {role!r}")
        model = job.get("model")
        model_key = SEMANTIC_ROLE_MODEL_KEYS[role]
        expected_model = _bare_agent_model(action.get("dispatch_values", {}).get(model_key))
        if model is not None and model != expected_model:
            raise ControllerError(f"dispatch model does not match semantic role {role!r}")
        if role == "stride_analyzer" and job.get("analysis_depth") not in {"full", "light"}:
            raise ControllerError("stride analyzer dispatch job requires analysis_depth full or light")
        component_projection_keys = (
            "repository_projection_path",
            "repository_projection_sha256",
            "business_context_path",
            "business_context_sha256",
            "architecture_context_path",
            "architecture_context_sha256",
            "security_context_projections",
        )
        if role != "stride_analyzer" and any(job.get(key) is not None for key in component_projection_keys):
            raise ControllerError("component projections are valid only for stride analyzer jobs")
        if role == "stride_analyzer":
            attempt = job.get("attempt")
            if not isinstance(component_id, str) or isinstance(attempt, bool) or not isinstance(attempt, int):
                raise ControllerError("stride analyzer job requires component and attempt identity")
            expected_job_suffix = f":attempt-{attempt}"
            if not job_id.endswith(expected_job_suffix):
                raise ControllerError("stride analyzer job id does not match its attempt identity")
            expected_output = stride_dispatch_waves.attempt_artifact(component_id, attempt)
            if job.get("output_artifacts") != [expected_output]:
                raise ControllerError("stride analyzer output does not match its exclusive attempt identity")
            expected_taxonomy = (
                f".taxonomy-slices/{component_id}/threat-category-taxonomy.yaml" if component_id else None
            )
            if job.get("taxonomy_slice_path") != expected_taxonomy:
                raise ControllerError("stride analyzer taxonomy slice does not match its component id")
            if expected_taxonomy not in job.get("input_artifacts", []):
                raise ControllerError("stride analyzer taxonomy slice is absent from input_artifacts")
            expected_plan = f".dispatch-context/{component_id}/context-plan.json" if component_id else None
            if job.get("context_plan_path") != expected_plan:
                raise ControllerError("stride analyzer component context plan does not match its component id")
            if expected_plan not in job.get("input_artifacts", []):
                raise ControllerError("stride analyzer component context plan is absent from input_artifacts")
            if ".stride-dispatch-manifest.json" in job.get("input_artifacts", []):
                raise ControllerError(
                    "stride analyzer must receive its component plan, not the shared dispatch manifest"
                )
            if ".stride-repository-registry.json" in job.get("input_artifacts", []):
                raise ControllerError(
                    "stride analyzer must receive component repository roots, not the shared registry"
                )
        all_inputs.update(job.get("input_artifacts", []))
        for artifact_path in job.get("output_artifacts", []):
            prior_owner = output_owners.get(artifact_path)
            if prior_owner is not None:
                raise ControllerError(
                    f"duplicate dispatch output artifact {artifact_path!r}: {prior_owner!r} and {job_id!r}"
                )
            output_owners[artifact_path] = job_id

    if action.get("action") == "dispatch_parallel":
        overlap = sorted(all_inputs & set(output_owners))
        if overlap:
            raise ControllerError("parallel dispatch cannot read and write the same artifact: " + ", ".join(overlap))

    output_root = _canonical_output_root(action)
    if output_root is not None:
        for job in action.get("dispatch_jobs", []):
            for key in ("input_artifacts", "output_artifacts"):
                for artifact_path in job.get(key, []):
                    _resolve_artifact_path(output_root, artifact_path)
            if job.get("semantic_role") == "stride_analyzer":
                _validate_stride_component_context_plan(
                    output_root,
                    job,
                    action.get("artifact_receipts", []),
                    action.get("dispatch_values", {}).get("stride_profile"),
                )
        for receipt in action.get("artifact_receipts", []):
            _resolve_artifact_path(output_root, receipt["artifact_path"])
        has_delivery_references = any(job.get("context_delivery_ids") for job in action.get("dispatch_jobs", []))
        if action.get("context_plan") is not None:
            try:
                context_routing.validate_action_plan_reference(action, output_root)
            except context_routing.ContextRoutingError as exc:
                raise ControllerError(f"active context routing validation failed: {exc}") from exc
        elif has_delivery_references:
            raise ControllerError("context delivery references require an effective-plan reference")


def _validate_action(action: dict[str, Any]) -> dict[str, Any]:
    if Draft202012Validator is None:
        raise ControllerError("internal action-manifest validation dependency is unavailable")
    if len(_canonical_json_bytes(action)) > MAX_ACTION_BYTES:
        raise ControllerError(f"internal action manifest exceeds the {MAX_ACTION_BYTES}-byte cap")
    schema = json.loads(ACTION_SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(action),
        key=lambda item: list(item.path),
    )
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise ControllerError(f"internal action-manifest validation failed: {detail}")
    _validate_action_semantics(action)
    return action


@cache
def _receipt_schema_registry():
    if Registry is None or Resource is None:
        raise ControllerError("cannot create artifact receipt: schema registry dependency is unavailable")
    registry = Registry()
    for name in (
        "actors.schema.yaml",
        "actors-discovered.schema.yaml",
        "actors-merged-static.schema.yaml",
        "actors-resolved.schema.yaml",
        "actors-repo.schema.yaml",
    ):
        import yaml

        value = yaml.safe_load((PLUGIN_ROOT / "schemas" / name).read_text(encoding="utf-8"))
        registry = registry.with_resource(value["$id"], Resource.from_contents(value))
    return registry


def create_artifact_receipt(
    output_root: Path,
    artifact_path: str,
    *,
    schema_id: str,
    record_count: int,
) -> dict[str, Any]:
    """Create a receipt from exact artifact bytes after structural validation."""
    path = _resolve_artifact_path(output_root.resolve(), artifact_path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot read validated artifact {artifact_path!r}: {exc}") from exc
    if schema_id not in _RECEIPT_RECORD_KEYS:
        raise ControllerError(f"artifact receipt names an unregistered schema: {schema_id}")
    schema_name = schema_id.split("#", 1)[0]
    schema_path = (PLUGIN_ROOT / schema_name).resolve()
    try:
        schema_path.relative_to((PLUGIN_ROOT / "schemas").resolve())
        value = json.loads(payload)
        if schema_path.suffix == ".json":
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        else:
            import yaml

            schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ControllerError(f"cannot validate exact artifact bytes for {artifact_path!r}: {exc}") from exc
    if Draft202012Validator is None:
        raise ControllerError("cannot create artifact receipt: jsonschema dependency is unavailable")
    try:
        errors = sorted(
            Draft202012Validator(schema, registry=_receipt_schema_registry()).iter_errors(value),
            key=lambda item: list(item.path),
        )
    except Exception as exc:
        raise ControllerError(f"artifact receipt schema resolution failed for {artifact_path!r}: {exc}") from exc
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise ControllerError(f"artifact receipt schema validation failed for {artifact_path!r}: {detail}")
    record_value = value.get(_RECEIPT_RECORD_KEYS[schema_id]) if isinstance(value, dict) else None
    if record_value is None and schema_id in _OPTIONAL_RECEIPT_RECORD_KEYS:
        record_value = []
    actual_count = len(record_value) if isinstance(record_value, (list, dict)) else None
    if actual_count is None or actual_count != record_count:
        raise ControllerError(
            f"artifact receipt record count is stale for {artifact_path!r}: expected {actual_count}, got {record_count}"
        )
    receipt = {
        "schema_version": 1,
        "artifact_path": artifact_path,
        "schema_id": schema_id,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": record_count,
        "validation_status": "valid",
    }
    _validate_action(
        {
            "schema_version": 1,
            "action": "run_gate",
            "dispatch_values": {"output_dir": str(output_root.resolve())},
            "artifact_receipts": [receipt],
        }
    )
    return receipt


def consume_artifact_receipt(output_root: Path, receipt: dict[str, Any]) -> bytes:
    """Re-read an artifact and reject bytes changed since receipt creation."""
    _validate_action(
        {
            "schema_version": 1,
            "action": "run_gate",
            "dispatch_values": {"output_dir": str(output_root.resolve())},
            "artifact_receipts": [receipt],
        }
    )
    artifact_path = receipt["artifact_path"]
    path = _resolve_artifact_path(output_root.resolve(), artifact_path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot consume artifact {artifact_path!r}: {exc}") from exc
    if hashlib.sha256(payload).hexdigest() != receipt["sha256"]:
        raise ControllerError(f"artifact changed after validation: {artifact_path}")
    return payload


def verify_receipt_hashes(output_root: Path, receipt_pairs: list[tuple[str, str]]) -> dict[str, Any]:
    """Re-hash one action's admitted inputs immediately before Agent dispatch."""
    if not receipt_pairs:
        raise ControllerError("receipt verification requires at least one artifact")
    if len(receipt_pairs) > 64:
        raise ControllerError("receipt verification exceeds the 64-artifact action cap")
    seen: set[str] = set()
    for artifact_path, expected_sha256 in receipt_pairs:
        if artifact_path in seen:
            raise ControllerError(f"duplicate receipt verification path: {artifact_path}")
        seen.add(artifact_path)
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise ControllerError(f"invalid receipt fingerprint for {artifact_path!r}")
        path = _resolve_artifact_path(output_root.resolve(), artifact_path)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ControllerError(f"cannot consume artifact {artifact_path!r}: {exc}") from exc
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ControllerError(f"artifact changed after validation: {artifact_path}")
    return _validate_action(
        {
            "schema_version": 1,
            "action": "run_gate",
            "dispatch_values": {"output_dir": str(output_root.resolve())},
            "receipts": [f"Verified {len(receipt_pairs)} artifact receipt(s) immediately before dispatch"],
        }
    )


def _emit(action: dict[str, Any]) -> int:
    try:
        action = _validate_action(action)
        if (
            action.get("instruction_file") in {str(THIN_STAGE1_V2_RUNTIME), str(THIN_STAGE1D_RUNTIME)}
            and action.get("action") in {"dispatch_agent", "dispatch_parallel"}
            and action.get("dispatch_jobs")
        ):
            try:
                plan = context_routing.resolve_action(
                    action,
                    Path(action["dispatch_values"]["output_dir"]),
                    semantic_roles=SEMANTIC_ROLE_REGISTRY,
                    model_keys=SEMANTIC_ROLE_MODEL_KEYS,
                    plugin_root=PLUGIN_ROOT,
                )
            except context_routing.ContextRoutingError as exc:
                raise ControllerError(f"context routing validation failed: {exc}") from exc
            try:
                action = context_routing.bind_action_to_plan(
                    action,
                    plan,
                    Path(action["dispatch_values"]["output_dir"]),
                )
            except context_routing.ContextRoutingError as exc:
                raise ControllerError(f"context routing action binding failed: {exc}") from exc
            action = _validate_action(action)
            # Every planned action now carries its identity reference, so plan
            # presence no longer distinguishes the two modes — the enforced
            # delivery count does.
            enforced = any(job.get("context_delivery_ids") for job in action.get("dispatch_jobs", []))
            event = "CONTEXT_ROUTING_ACTIVE" if enforced else "CONTEXT_ROUTING_SHADOW"
            _append_event(
                Path(action["dispatch_values"]["output_dir"]),
                event,
                f"revision={plan['revision']} actions={len(plan['actions'])} deliveries={len(plan['deliveries'])}",
            )
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
    thin_eligible = resolve_config.compact_runtime_eligible(cfg)
    if cfg.get("runtime_generation") == CONTEXT_V2_GENERATION and not thin_eligible:
        raise ControllerError("incompatible runtime selection: context-v2 requires the compact top-level runtime")
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


_FAILURE_MARKERS = ("FATAL", "INVALID", "ERROR", "Traceback")
_EXIT_LEAD_RE = re.compile(r"^(.*?failed with exit -?\d+:)")


def _abort_event_detail(reason: str) -> str:
    """One event-safe line whose headline names the actual failure.

    A script's stderr leads with its warnings, so the first line of a failure is
    routinely benign — a run died on `INVALID: threats[18].title …` and reported
    `threats: 5 below severity floor … dropped from register`, which reads like
    normal filtering and sent two readers down the wrong path. A multi-line
    detail also breaks the one-line-per-event log format, leaving every
    continuation line unparseable.
    """
    lines = [line.strip() for line in str(reason).splitlines() if line.strip()]
    if not lines:
        return ""
    head = lines[0]
    # The last marker line, not the first: a validator prints its class
    # ("FATAL: schema validation failed") before the finding that caused it
    # ("INVALID: threats[18].title …"), and the finding is what a reader acts on.
    salient = next((line for line in reversed(lines[1:]) if line.startswith(_FAILURE_MARKERS)), "")
    extra = f"  (+{len(lines) - 1} more line(s))" if len(lines) > 1 else ""
    if not salient:
        return f"{head}{extra}"
    lead = _EXIT_LEAD_RE.match(head)
    return f"{lead.group(1) if lead else head} {salient}{extra}"


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
    # The redaction sweep covers the deliverables and the finding pipeline; the
    # intermediates it walks past stay unredacted because they are never meant
    # to be published. Establish that assumption here rather than relying on
    # it — publish-threat-model then lifts individual deliverables back out.
    # No-op when a rule already exists or the directory is not in a work tree.
    ensure_output_gitignore.ensure(output_dir)
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


def _need_render_recovery_reason(output_dir: Path) -> str:
    """Describe the supported recovery without crossing runtime generations."""
    try:
        persisted = json.loads((output_dir / ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        persisted = {}
    if persisted.get("runtime_generation") == CONTEXT_V2_GENERATION:
        return (
            "Stage 1 is complete (phase=10b need_render=true), but context-v2 "
            "does not support --resume. Repeat --rebuild --force to start a "
            "fresh run and discard the incomplete assessment."
        )
    return (
        "Stage 1 is complete (phase=10b need_render=true). Use --resume to "
        "render it, or repeat --rebuild --force to discard the completed analysis."
    )


def _boundary_budget_abort_reason(cfg: dict[str, Any]) -> str:
    if cfg.get("runtime_generation") == CONTEXT_V2_GENERATION:
        return (
            "Stage 1b was not dispatched because the Stage-1a turn budget was "
            "exhausted. Context-v2 retained the assessment input for diagnostics "
            "but cannot resume it; start a fresh full or rebuild run."
        )
    return (
        "Stage 1b was not dispatched because the Stage-1a turn budget was exhausted; "
        "the immutable assessment input was preserved for --resume"
    )


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
            "reason": _need_render_recovery_reason(output_dir),
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
        "instruction_file": str(_stage1_runtime_for(cfg)),
        "task_rows": _task_rows(cfg),
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
    *,
    fatal_exit_codes: tuple[int, ...] = (),
) -> bool:
    """Run a script, tolerating failure — except for `fatal_exit_codes`.

    Some scripts have a genuinely soft failure mode (nothing to do, an absent
    input, a cosmetic pass) and a hard one that leaves the run in a state the
    report must not be built from. `fatal_exit_codes` names the latter so the
    caller can keep the tolerant default without downgrading a hard failure to
    a receipt string.
    """
    try:
        _run_script(name, args)
        return True
    except ControllerError as exc:
        if exc.exit_code in fatal_exit_codes:
            raise
        receipts.append(f"{name}: best-effort failure")
        _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")
        return False


def _run_auto_emitter_pass(output_dir: Path, cfg: dict[str, Any], receipts: list[str]) -> None:
    """Apply the shared deterministic YAML enrichment before quality gates."""
    try:
        _run_external(
            [
                "bash",
                str(SCRIPT_DIR / "auto_emitter_pass.sh"),
                str(output_dir),
                str(cfg.get("repo_root") or output_dir),
                str(PLUGIN_ROOT),
                "true" if cfg.get("dry_run") else "false",
            ]
        )
    except ControllerError as exc:
        receipts.append("auto_emitter_pass.sh: best-effort failure")
        _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")


def _load_json_object(path: Path, *, contract: str) -> dict[str, Any]:
    """Load a controller-consumed JSON object or fail at the boundary."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControllerError(f"cannot read {contract} artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ControllerError(f"{contract} artifact must be a JSON object: {path}")
    return value


def _validate_json_artifact(path: Path, schema_path: Path, *, contract: str) -> dict[str, Any]:
    """Validate one JSON artifact with the required structural dependency."""
    if Draft202012Validator is None:
        raise ControllerError(f"cannot validate {contract}: jsonschema dependency is unavailable")
    value = _load_json_object(path, contract=contract)
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControllerError(f"cannot load schema for {contract}: {exc}") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise ControllerError(f"{contract} validation failed: {detail}")
    return value


def _validate_yaml_artifact(path: Path, schema_path: Path, *, contract: str) -> dict[str, Any]:
    """Validate one YAML artifact with the required structural dependency."""
    if Draft202012Validator is None:
        raise ControllerError(f"cannot validate {contract}: jsonschema dependency is unavailable")
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ControllerError(f"cannot load {contract} artifact or schema: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(schema, dict):
        raise ControllerError(f"{contract} artifact and schema must be mappings")
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise ControllerError(f"{contract} validation failed: {detail}")
    return value


def _validate_evidence_verification(path: Path, threats_path: Path | None = None) -> dict[str, Any]:
    """Validate the evidence side channel's structural and count contracts."""
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "evidence-verification.schema.json",
        contract="evidence-verification-v1",
    )
    valid, semantic_errors = intermediate_contract.validate_evidence_verification(value)
    if not valid:
        raise ControllerError(f"evidence-verification-v1 {semantic_errors[0]}")
    summary = value["summary"]
    total = summary["total_threats"]
    flags = value["flags"]
    if threats_path is not None:
        merged = _load_json_object(threats_path, contract="threats-merged-v1")
        threats = merged.get("threats")
        if not isinstance(threats, list):
            raise ControllerError("threats-merged-v1 artifact has no threats array")
        if total != len(threats):
            raise ControllerError("evidence-verification-v1 total_threats does not match the merged threat count")
        by_id = {
            threat.get("t_id"): threat
            for threat in threats
            if isinstance(threat, dict) and isinstance(threat.get("t_id"), str)
        }
        for flag in flags:
            threat = by_id.get(flag["t_id"])
            if threat is None:
                raise ControllerError(f"evidence-verification-v1 references unknown threat {flag['t_id']}")
            if threat.get("evidence_check") != flag["verdict"]:
                raise ControllerError(f"evidence-verification-v1 verdict does not match merged threat {flag['t_id']}")
            annotations = threat.get("evidence_flags")
            if not isinstance(annotations, list) or not any(
                isinstance(annotation, dict)
                and annotation.get("flag_id") == flag["flag_id"]
                and annotation.get("verdict") == flag["verdict"]
                for annotation in annotations
            ):
                raise ControllerError(f"evidence-verification-v1 flag is absent from merged threat {flag['t_id']}")
    return value


def _validate_recon_signals(path: Path, repo_root: Path) -> dict[str, Any]:
    """Validate the mandatory bounded actor/architecture signal artifact."""
    try:
        byte_count = path.stat().st_size
    except OSError as exc:
        raise ControllerError(f"cannot stat recon-signals-v2 artifact {path}: {exc}") from exc
    if byte_count > MAX_RECON_SIGNALS_BYTES:
        raise ControllerError(f"recon-signals-v2 artifact exceeds the {MAX_RECON_SIGNALS_BYTES}-byte cap")
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "recon-signals.schema.json",
        contract="recon-signals-v2",
    )
    valid, semantic_errors = intermediate_contract.validate_recon_signals(value, repo_root=repo_root)
    if not valid:
        raise ProducerContractError(
            f"recon-signals-v2 {semantic_errors[0]}",
            [f"signal_evidence: {error}" for error in semantic_errors],
        )
    return value


@cache
def _required_recon_headings() -> tuple[str, ...]:
    """Expose the shared contract headings for controller fixtures."""
    try:
        return recon_summary_contract.required_headings()
    except recon_summary_contract.ReconSummaryValidationError as exc:
        raise ControllerError(str(exc)) from exc


def _validate_recon_summary(path: Path, repo_root: Path | None = None) -> None:
    """Validate the shared Markdown contract consumed downstream."""
    try:
        recon_summary_contract.validate_recon_summary(path, repo_root=repo_root)
    except recon_summary_contract.ReconSummaryValidationError as exc:
        raise ControllerError(str(exc)) from exc


def _validate_threat_modeling_context(path: Path) -> None:
    """Validate the shared bounded-context Markdown contract."""
    try:
        context_document_contract.validate_threat_modeling_context(path)
    except context_document_contract.ThreatModelingContextValidationError as exc:
        raise ControllerError(str(exc)) from exc


def _repair_missing_threat_modeling_context_headings(path: Path) -> tuple[str, ...]:
    """Apply the contract-owned, omission-only context normalization."""
    try:
        return context_document_contract.repair_missing_headings(path)
    except context_document_contract.ThreatModelingContextValidationError as exc:
        raise ControllerError(str(exc)) from exc


def _normalize_context_v2_analyst_context(output_dir: Path) -> None:
    """Remove routing state that the context-v2 semantic producer does not own."""
    path = output_dir / ".stride-analyst-context.json"
    _check_context_v2_analyst_context_size(path)
    value = _load_json_object(path, contract="stride-analyst-context-v1")
    if "_stride_profile" not in value:
        return
    value.pop("_stride_profile")
    from _atomic_io import atomic_write_json

    atomic_write_json(path, value, sort_keys=False)
    _append_event(
        output_dir,
        "CONTEXT_V2_RESERVED_FIELD_DROPPED",
        "removed producer-authored _stride_profile; resolved run configuration is authoritative",
        level="WARN",
    )


def _check_context_v2_analyst_context_size(path: Path) -> None:
    """Reject an unbounded producer artifact before parsing it."""
    try:
        byte_count = path.stat().st_size
    except OSError as exc:
        raise ControllerError(f"cannot stat stride-analyst-context-v1 artifact {path}: {exc}") from exc
    if byte_count > MAX_STRIDE_ANALYST_CONTEXT_BYTES:
        raise ControllerError(
            f"stride-analyst-context-v1 artifact exceeds the {MAX_STRIDE_ANALYST_CONTEXT_BYTES}-byte cap"
        )


def _validate_context_v2_analyst_context(
    output_dir: Path,
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Validate the bounded semantic overlay against finalized component IDs."""
    path = output_dir / ".stride-analyst-context.json"
    _check_context_v2_analyst_context_size(path)
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "stride-analyst-context.schema.json",
        contract="stride-analyst-context-v1",
    )
    components = _load_json_object(output_dir / ".components.json", contract="components-v1").get("components")
    if not isinstance(components, list):
        raise ControllerError("components-v1 artifact has no components array")
    component_ids = {
        component.get("id")
        for component in components
        if isinstance(component, dict) and isinstance(component.get("id"), str)
    }
    unknown = sorted(set(value) - component_ids)
    if unknown:
        raise ControllerError("stride-analyst-context-v1 contains unknown component IDs: " + ", ".join(unknown[:10]))
    if repo_root is not None:
        valid, errors = intermediate_contract.validate_stride_analyst_context(
            value,
            output_dir=output_dir,
            repo_root=repo_root,
        )
        if not valid:
            raise ControllerError("stride-analyst-context-v1 routing validation failed: " + "; ".join(errors[:10]))
    return value


def _load_context_v2_config(output_dir: Path) -> tuple[Path, dict[str, Any]]:
    """Load durable run state and refuse to continue under another generation.

    The generation is read from the run's persisted config, never from the
    current environment: the producer that already wrote artifacts into this
    output directory is the only one allowed to continue writing them. An
    operator who changes APPSEC_CONTEXT_V2 mid-run gets an explicit
    incompatible-state abort instead of a second producer for one artifact.
    """
    output_dir, cfg = _load_run_config(output_dir)
    generation = cfg.get("runtime_generation") or LEGACY_GENERATION
    if generation != CONTEXT_V2_GENERATION:
        raise ControllerError(
            f"incompatible runtime generation: this run was prepared as {generation!r} and a "
            "context-v2 action cannot continue it. Select the prior runtime for this "
            "invocation, or start a new eligible full/rebuild run."
        )
    versions = cfg.get("runtime_artifact_schema_versions")
    expected_versions = resolve_config.CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS
    if versions != expected_versions:
        raise ControllerError(
            "incompatible context-v2 artifact schema versions; start a new run with the current plugin generation"
        )
    if cutoff_cause.detect_abort(output_dir):
        raise ControllerError(
            "this context-v2 invocation already reached an authoritative RUN_ABORTED state; "
            "no later boundary or semantic producer may continue it"
        )
    env_override = os.environ.get("APPSEC_CONTEXT_V2", "").strip()
    if env_override not in ("", "1"):
        _append_event(
            output_dir,
            "RUNTIME_GENERATION_ENV_IGNORED",
            "continuing persisted runtime_generation=context-v2; the current APPSEC_CONTEXT_V2 override selects legacy",
            level="WARN",
        )
    return output_dir, cfg


def _stage1_runtime_for(cfg: dict[str, Any]) -> Path:
    """The Stage-1 runtime for this run's persisted producer generation."""
    if (cfg.get("runtime_generation") or LEGACY_GENERATION) == CONTEXT_V2_GENERATION:
        return THIN_STAGE1_V2_RUNTIME
    return THIN_STAGE1_RUNTIME


STAGE1_TASK_ROWS_CONTEXT_V2 = (
    "Stage 1a [1/3] - Recon scan",
    "Stage 1a [2/3] - Actor discovery",
    "Stage 1a [3/3] - Architecture modeling",
    "Stage 1b [1/1] - Trust boundaries",
    "Stage 1c [1/6] - Security controls",
    "Stage 1c [2/6] - STRIDE analysis",
    "Stage 1c [3/6] - Threat merge",
    "Stage 1c [4/6] - Evidence verification",
    "Stage 1c [5/6] - Triage",
    "Stage 1c [6/6] - Root causes",
)

STAGE1_TASK_ROWS_LEGACY = (
    "Stage 1a - Discovery & Architecture Modeling",
    "Stage 1b - Trust Boundary Analysis",
    "Stage 1c - Control & Threat Analysis",
)


def _stage1_task_rows(cfg: dict[str, Any]) -> list[str]:
    """The Stage-1 task rows the session creates before it dispatches.

    Context-v2 returns control to the session at every job, so Stage 1 can show
    which part of it is running instead of one row for its whole duration. Each
    row names its stage and its position within that stage's substages, so the
    reader can tell how far the running stage has left to go. The legacy runtime
    has no comparable seam and keeps its undivided stage rows.
    """
    if _stage1_runtime_for(cfg) == THIN_STAGE1_V2_RUNTIME:
        return list(STAGE1_TASK_ROWS_CONTEXT_V2)
    return list(STAGE1_TASK_ROWS_LEGACY)


def _task_rows(cfg: dict[str, Any]) -> list[str]:
    """Every task row the session creates, in creation order.

    The rows a run shows depend on the abuse-case, QA and architect switches,
    and the closing row depends on whether cleanup runs. Deciding that here
    keeps the labels off the session's prompt budget and out of its own
    invention: a subject the session authors is a subject a later `TaskUpdate`
    no longer matches.
    """
    rows = ["Preparing workspace"]
    rows.extend(_stage1_task_rows(cfg))
    if not cfg.get("skip_abuse_case_verification"):
        rows.append("Stage 1d - Abuse Case Verification")
    rows.append("Stage 2 - Report Rendering")
    if not cfg.get("skip_qa"):
        rows.append("Stage 3 - QA Review")
    if cfg.get("architect_review"):
        rows.append("Stage 4 - Architect Review")
    rows.append("Final summary" if cfg.get("keep_runtime_files") else "Final summary + cleanup")
    return rows


def _reject_context_v2(cfg: dict[str, Any], stage: str) -> None:
    """Keep a legacy Stage-1 gate off a context-v2 run.

    Context-v2 has its own terminal Stage-1 gate. Letting a legacy gate also
    run would put two producers on the same artifacts inside one invocation.
    """
    if (cfg.get("runtime_generation") or LEGACY_GENERATION) == CONTEXT_V2_GENERATION:
        raise ControllerError(
            f"incompatible runtime generation: {stage} is a legacy-producer gate and this run was "
            "prepared as 'context-v2'. Use the context-v2 actions for this run."
        )


def _context_v2_common(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mode": cfg["mode"],
        "stage": "stage1c",
        "instruction_file": str(THIN_STAGE1_V2_RUNTIME),
        "config_path": str(output_dir / ".skill-config.json"),
        "dispatch_values": _dispatch_values(cfg),
    }


def _bare_agent_model(value: Any) -> str:
    """Reduce an operator-selected model ID to Claude Agent's closed aliases."""
    lowered = str(value or "sonnet").lower()
    for alias in ("opus", "haiku", "sonnet"):
        if alias in lowered:
            return alias
    return "sonnet"


def _context_v2_job_metadata(cfg: dict[str, Any], role: str) -> dict[str, str]:
    record = SEMANTIC_ROLE_REGISTRY.get(role)
    model_key = SEMANTIC_ROLE_MODEL_KEYS.get(role)
    if record is None or model_key is None:
        raise ControllerError(f"unknown semantic role: {role!r}")
    if role not in CONTEXT_V2_PRODUCER_GATED_ROLES | CONTEXT_V2_CONTROLLER_RECOVERY_ROLES:
        raise ControllerError(f"semantic role has no pre-handoff contract enforcement: {role!r}")
    return {
        "agent_type": f"appsec-advisor:{record['agent']}",
        "model": _bare_agent_model(cfg.get(model_key)),
    }


def _context_v2_taxonomy_slice(output_dir: Path, component_id: str) -> tuple[str, str]:
    """Build the bounded canonical CWE-to-TH input for one STRIDE job."""
    _run_script(
        "slice_taxonomy.py",
        [
            component_id,
            str(output_dir),
            "--component-id",
            component_id,
            "--data-dir",
            str(PLUGIN_ROOT / "data"),
            "--taxonomies",
            "threats",
        ],
        acceptable=(0, 1),
    )
    relative = f".taxonomy-slices/{component_id}/threat-category-taxonomy.yaml"
    path = _resolve_artifact_path(output_dir.resolve(), relative)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot read context-v2 taxonomy slice for {component_id}: {exc}") from exc
    if not payload or len(payload) > 32_768:
        raise ControllerError(f"context-v2 taxonomy slice for {component_id} is empty or exceeds 32768 bytes")
    value = _validate_yaml_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "threat-taxonomy-slice.schema.yaml",
        contract="threat-taxonomy-slice-v1",
    )
    category_ids = [row.get("id") for row in value["categories"]]
    if len(category_ids) != len(set(category_ids)):
        raise ControllerError(f"threat-taxonomy-slice-v1 has duplicate category IDs for {component_id}")
    category_id_set = set(category_ids)
    unknown = sorted(
        {
            threat_id
            for threat_ids in value["cwe_to_th"].values()
            for threat_id in threat_ids
            if threat_id not in category_id_set
        }
    )
    if unknown:
        raise ControllerError(
            f"threat-taxonomy-slice-v1 maps CWEs to absent categories for {component_id}: {', '.join(unknown)}"
        )
    return relative, hashlib.sha256(payload).hexdigest()


def _run_llm_policy(output_dir: Path) -> dict[str, Any] | None:
    """The organization's LLM policy from the resolved org profile, or None.

    Read once per dispatch build. A profile without the block, an inactive
    profile, and an unreadable file are the same answer: nothing was declared,
    so the analyzer must not answer the two policy questions at all."""
    try:
        effective = json.loads((output_dir / ".org-profile-effective.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    policy = effective.get("llm_policy") if isinstance(effective, dict) else None
    if not isinstance(policy, dict):
        return None
    attributes = {
        name: [item for item in policy[name] if isinstance(item, str) and item.strip()]
        for name in ("permitted_data_classes", "approval_required_actions")
        if isinstance(policy.get(name), list) and policy[name]
    }
    attributes = {name: value for name, value in attributes.items() if value}
    return attributes or None


def _write_stride_component_llm_policy(
    output_dir: Path,
    *,
    component_id: str,
    attributes: dict[str, Any] | None,
) -> tuple[str, dict[str, Any]] | None:
    """Project the run's LLM policy for one component, or nothing to project."""
    from _atomic_io import atomic_write_json

    if not attributes:
        return None
    relative = f".dispatch-context/{component_id}/llm-policy.json"
    path = _resolve_artifact_path(output_dir, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        path,
        {
            "schema_version": 1,
            "component_id": component_id,
            "source": "org-profile-llm-policy-v1",
            "attributes": attributes,
        },
        sort_keys=True,
    )
    receipt = _validated_json_receipt(
        output_dir,
        relative,
        schema_id="schemas/stride-run-llm-policy.schema.json#v1",
        record_count=len(attributes),
    )
    return relative, receipt


def _write_stride_component_context_plan(
    output_dir: Path,
    *,
    component_id: str,
    manifest_sha256: str,
    analysis: dict[str, Any],
    lens_ids: list[str],
    bundle_path: str,
    bundle_sha256: str,
    taxonomy_path: str,
    taxonomy_sha256: str,
    architecture_context_path: str | None = None,
    architecture_context_sha256: str | None = None,
    business_context_path: str | None = None,
    business_context_sha256: str | None = None,
    llm_policy_path: str | None = None,
    llm_policy_sha256: str | None = None,
    repository_projection_path: str | None = None,
    repository_projection_sha256: str | None = None,
    security_context_projections: list[dict[str, str]] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Write one bounded STRIDE admission plan derived from validated inputs."""
    from _atomic_io import atomic_write_json

    relative = f".dispatch-context/{component_id}/context-plan.json"
    path = _resolve_artifact_path(output_dir.resolve(), relative)
    inputs = [
        {
            "context_id": "controls.component_evidence",
            "artifact_path": bundle_path,
            "sha256": bundle_sha256,
        },
        {
            "context_id": "threats.component_taxonomy",
            "artifact_path": taxonomy_path,
            "sha256": taxonomy_sha256,
        },
    ]
    if (architecture_context_path is None) != (architecture_context_sha256 is None):
        raise ControllerError("component architecture-context path and hash must be supplied together")
    if architecture_context_path is not None and architecture_context_sha256 is not None:
        inputs.append(
            {
                "context_id": "architecture.component_context",
                "artifact_path": architecture_context_path,
                "sha256": architecture_context_sha256,
            }
        )
    if (business_context_path is None) != (business_context_sha256 is None):
        raise ControllerError("component business-context path and hash must be supplied together")
    if business_context_path is not None and business_context_sha256 is not None:
        inputs.append(
            {
                "context_id": "business.component_context",
                "artifact_path": business_context_path,
                "sha256": business_context_sha256,
            }
        )
    if (llm_policy_path is None) != (llm_policy_sha256 is None):
        raise ControllerError("component llm-policy path and hash must be supplied together")
    if llm_policy_path is not None and llm_policy_sha256 is not None:
        inputs.append(
            {
                "context_id": "policy.llm_policy",
                "artifact_path": llm_policy_path,
                "sha256": llm_policy_sha256,
            }
        )
    if (repository_projection_path is None) != (repository_projection_sha256 is None):
        raise ControllerError("component repository projection path and hash must be supplied together")
    if repository_projection_path is not None and repository_projection_sha256 is not None:
        inputs.append(
            {
                "context_id": "threats.related_repositories",
                "artifact_path": repository_projection_path,
                "sha256": repository_projection_sha256,
            }
        )
    for projection in security_context_projections or []:
        inputs.append(
            {
                "context_id": projection["context_id"],
                "artifact_path": projection["artifact_path"],
                "sha256": projection["sha256"],
            }
        )
    value = {
        "schema_version": 1,
        "component_id": component_id,
        "source_manifest_sha256": manifest_sha256,
        "analysis": analysis,
        "lens_ids": lens_ids,
        "inputs": inputs,
    }
    atomic_write_json(path, value, sort_keys=True)
    receipt = _validated_json_receipt(
        output_dir,
        relative,
        schema_id="schemas/stride-component-context-plan.schema.json#v1",
        record_count=len(inputs),
    )
    return relative, receipt


def _write_stride_component_repository_roots(
    output_dir: Path,
    *,
    component_id: str,
    bundle: dict[str, Any],
    source_registry_path: Path,
) -> tuple[str, dict[str, Any]] | None:
    """Project only related roots referenced by one component's source slices."""
    from _atomic_io import atomic_write_json

    slices = bundle.get("source_slices")
    if not isinstance(slices, list):
        raise ControllerError(f"stride-evidence-bundle-v1 has no source_slices for {component_id}")
    referenced_ids_raw = {
        row.get("repository_id") for row in slices if isinstance(row, dict) and row.get("repository_id") != "primary"
    }
    if any(not isinstance(repository_id, str) for repository_id in referenced_ids_raw):
        raise ControllerError(f"evidence bundle contains an invalid related repository id for {component_id}")
    referenced_ids = sorted(referenced_ids_raw)
    if not referenced_ids:
        return None
    if len(referenced_ids) > 16:
        raise ControllerError(f"component {component_id} exceeds the 16-related-repository projection cap")

    source_registry = _validate_json_artifact(
        source_registry_path,
        PLUGIN_ROOT / "schemas" / "stride-repository-registry.schema.json",
        contract="stride-repository-registry-v1",
    )
    source_rows = source_registry.get("repositories")
    if not isinstance(source_rows, list):
        raise ControllerError("stride-repository-registry-v1 has no repositories array")
    source_by_id = {row.get("repository_id"): row for row in source_rows if isinstance(row, dict)}
    if len(source_by_id) != len(source_rows):
        raise ControllerError("stride-repository-registry-v1 contains duplicate repository ids")
    missing = sorted(set(referenced_ids) - set(source_by_id))
    if missing:
        raise ControllerError(
            f"component {component_id} references repositories absent from the controller registry: "
            + ", ".join(missing)
        )
    source_payload = source_registry_path.read_bytes()
    relative = f".dispatch-context/{component_id}/repository-roots.json"
    path = _resolve_artifact_path(output_dir.resolve(), relative)
    value = {
        "schema_version": 1,
        "component_id": component_id,
        "source_registry_sha256": hashlib.sha256(source_payload).hexdigest(),
        "repositories": [
            {
                "repository_id": repository_id,
                "kind": "related",
                "root": source_by_id[repository_id]["root"],
            }
            for repository_id in referenced_ids
        ],
    }
    atomic_write_json(path, value, sort_keys=True)
    receipt = _validated_json_receipt(
        output_dir,
        relative,
        schema_id="schemas/stride-component-repository-roots.schema.json#v1",
        record_count=len(referenced_ids),
    )
    return relative, receipt


def _validate_stride_component_repository_roots(
    output_root: Path,
    job: dict[str, Any],
    bundle: dict[str, Any],
    artifact_receipts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Reconstruct and validate the exact related-root projection for one job."""
    component_id = job.get("component_id")
    slices = bundle.get("source_slices")
    if not isinstance(slices, list):
        raise ControllerError(f"stride-evidence-bundle-v1 has no source_slices for {component_id}")
    related_ids_raw = {
        row.get("repository_id") for row in slices if isinstance(row, dict) and row.get("repository_id") != "primary"
    }
    if any(not isinstance(repository_id, str) for repository_id in related_ids_raw):
        raise ControllerError(f"evidence bundle contains an invalid related repository id for {component_id}")
    related_ids = sorted(related_ids_raw)
    expected_path = f".dispatch-context/{component_id}/repository-roots.json"
    declared_path = job.get("repository_projection_path")
    declared_hash = job.get("repository_projection_sha256")
    inputs = job.get("input_artifacts", [])
    if not related_ids:
        if declared_path is not None or declared_hash is not None or expected_path in inputs:
            raise ControllerError("stride analyzer received related-repository roots without admitted related evidence")
        return None
    if declared_path != expected_path or expected_path not in inputs:
        raise ControllerError("stride analyzer related-repository projection does not match its component id")

    path = _resolve_artifact_path(output_root, expected_path)
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "stride-component-repository-roots.schema.json",
        contract="stride-component-repository-roots-v1",
    )
    payload = path.read_bytes()
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != declared_hash:
        raise ControllerError("stride analyzer related-repository projection hash is stale")
    matching_receipts = [row for row in artifact_receipts if row.get("artifact_path") == expected_path]
    if len(matching_receipts) != 1:
        raise ControllerError("stride analyzer related-repository projection requires one exact-byte receipt")
    if matching_receipts[0] != {
        "schema_version": 1,
        "artifact_path": expected_path,
        "schema_id": "schemas/stride-component-repository-roots.schema.json#v1",
        "sha256": actual_sha256,
        "record_count": len(related_ids),
        "validation_status": "valid",
    }:
        raise ControllerError("stride analyzer related-repository projection receipt is stale")
    if value.get("component_id") != component_id:
        raise ControllerError("stride analyzer related-repository projection contains another component")
    rows = value.get("repositories")
    projected_by_id = {row.get("repository_id"): row for row in rows if isinstance(row, dict)}
    if len(projected_by_id) != len(rows) or sorted(projected_by_id) != related_ids:
        raise ControllerError("related-repository projection does not match the bundle source slices")

    source_path = _resolve_artifact_path(output_root, ".stride-repository-registry.json")
    source_payload = source_path.read_bytes()
    if hashlib.sha256(source_payload).hexdigest() != value.get("source_registry_sha256"):
        raise ControllerError("related-repository projection is stale for the controller registry")
    source = _validate_json_artifact(
        source_path,
        PLUGIN_ROOT / "schemas" / "stride-repository-registry.schema.json",
        contract="stride-repository-registry-v1",
    )
    source_rows = source.get("repositories")
    source_by_id = {row.get("repository_id"): row for row in source_rows if isinstance(row, dict)}
    if len(source_by_id) != len(source_rows):
        raise ControllerError("stride-repository-registry-v1 contains duplicate repository ids")
    expected_rows = {
        repository_id: {
            "repository_id": repository_id,
            "kind": "related",
            "root": source_by_id.get(repository_id, {}).get("root"),
        }
        for repository_id in related_ids
    }
    if projected_by_id != expected_rows or any(row["root"] is None for row in expected_rows.values()):
        raise ControllerError("related-repository projection drifted from the controller registry")
    state_rows = bundle.get("repository_state")
    state_ids = (
        {row.get("repository_id") for row in state_rows if isinstance(row, dict)}
        if isinstance(state_rows, list)
        else set()
    )
    if state_ids != {"primary", *related_ids} or len(state_ids) != len(state_rows):
        raise ControllerError("evidence bundle repository state is not component-scoped")
    return value


def _validate_stride_component_architecture_context(
    output_root: Path,
    job: dict[str, Any],
    artifact_receipts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Validate an optional architecture projection that can be withheld independently."""
    component_id = job.get("component_id")
    expected_path = f".dispatch-context/{component_id}/architecture-context.json"
    declared_path = job.get("architecture_context_path")
    declared_hash = job.get("architecture_context_sha256")
    inputs = job.get("input_artifacts", [])
    if declared_path is None and declared_hash is None:
        if expected_path in inputs:
            raise ControllerError("stride analyzer received undeclared component architecture context")
        return None
    if declared_path != expected_path or expected_path not in inputs or not isinstance(declared_hash, str):
        raise ControllerError("stride analyzer architecture-context projection does not match its component id")
    path = _resolve_artifact_path(output_root, expected_path)
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "stride-component-architecture-context.schema.json",
        contract="stride-component-architecture-context-v1",
    )
    payload = path.read_bytes()
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != declared_hash:
        raise ControllerError("stride analyzer architecture-context projection hash is stale")
    attributes = value.get("attributes")
    if value.get("component_id") != component_id or not isinstance(attributes, dict) or not attributes:
        raise ControllerError("stride analyzer architecture-context projection has invalid component content")
    expected_source_sha = hashlib.sha256(_canonical_json_bytes(attributes)).hexdigest()
    if value.get("source_content_sha256") != expected_source_sha:
        raise ControllerError("stride analyzer architecture-context source fingerprint is stale")
    matching_receipts = [row for row in artifact_receipts if row.get("artifact_path") == expected_path]
    if len(matching_receipts) != 1 or matching_receipts[0] != {
        "schema_version": 1,
        "artifact_path": expected_path,
        "schema_id": "schemas/stride-component-architecture-context.schema.json#v1",
        "sha256": actual_sha256,
        "record_count": len(attributes),
        "validation_status": "valid",
    }:
        raise ControllerError("stride analyzer architecture-context projection receipt is stale")
    return value


def _validate_stride_component_llm_policy(
    output_dir: Path,
    job: dict[str, Any],
    artifact_receipts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Validate the optional organization LLM policy projected for a component."""
    component_id = job.get("component_id")
    expected_path = f".dispatch-context/{component_id}/llm-policy.json"
    declared_path = job.get("llm_policy_path")
    declared_hash = job.get("llm_policy_sha256")
    inputs = job.get("input_artifacts", [])
    if declared_path is None and declared_hash is None:
        if expected_path in inputs:
            raise ControllerError("stride analyzer received an undeclared llm policy")
        return None
    if declared_path != expected_path or expected_path not in inputs or not isinstance(declared_hash, str):
        raise ControllerError("stride analyzer llm-policy projection does not match its component id")
    path = _resolve_artifact_path(output_dir, expected_path)
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "stride-run-llm-policy.schema.json",
        contract="stride-run-llm-policy-v1",
    )
    if hashlib.sha256(path.read_bytes()).hexdigest() != declared_hash:
        raise ControllerError("stride analyzer llm-policy projection hash is stale")
    attributes = value.get("attributes")
    if value.get("component_id") != component_id or not isinstance(attributes, dict) or not attributes:
        raise ControllerError("stride analyzer llm-policy projection has invalid component content")
    matching_receipts = [row for row in artifact_receipts if row.get("artifact_path") == expected_path]
    if len(matching_receipts) != 1:
        raise ControllerError("stride analyzer llm-policy projection lacks exactly one receipt")
    return value


def _validate_stride_component_business_context(
    output_root: Path,
    job: dict[str, Any],
    artifact_receipts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Validate an optional business projection that can be withheld independently."""
    component_id = job.get("component_id")
    expected_path = f".dispatch-context/{component_id}/business-context.json"
    declared_path = job.get("business_context_path")
    declared_hash = job.get("business_context_sha256")
    inputs = job.get("input_artifacts", [])
    if declared_path is None and declared_hash is None:
        if expected_path in inputs:
            raise ControllerError("stride analyzer received undeclared component business context")
        return None
    if declared_path != expected_path or expected_path not in inputs or not isinstance(declared_hash, str):
        raise ControllerError("stride analyzer business-context projection does not match its component id")
    path = _resolve_artifact_path(output_root, expected_path)
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "stride-component-business-context.schema.json",
        contract="stride-component-business-context-v1",
    )
    payload = path.read_bytes()
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != declared_hash:
        raise ControllerError("stride analyzer business-context projection hash is stale")
    attributes = value.get("attributes")
    if value.get("component_id") != component_id or not isinstance(attributes, dict) or not attributes:
        raise ControllerError("stride analyzer business-context projection has invalid component content")
    expected_source_sha = hashlib.sha256(_canonical_json_bytes(attributes)).hexdigest()
    if value.get("source_content_sha256") != expected_source_sha:
        raise ControllerError("stride analyzer business-context source fingerprint is stale")
    matching_receipts = [row for row in artifact_receipts if row.get("artifact_path") == expected_path]
    if len(matching_receipts) != 1 or matching_receipts[0] != {
        "schema_version": 1,
        "artifact_path": expected_path,
        "schema_id": "schemas/stride-component-business-context.schema.json#v1",
        "sha256": actual_sha256,
        "record_count": len(attributes),
        "validation_status": "valid",
    }:
        raise ControllerError("stride analyzer business-context projection receipt is stale")
    return value


def _validate_stride_component_security_contexts(
    output_root: Path,
    job: dict[str, Any],
    artifact_receipts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate independently selectable component security-context projections."""
    from build_stride_evidence_bundles import (
        INLINE_SECURITY_CONTEXT_SPECS,
        SECURITY_CONTEXT_SPECS,
        component_security_context_projections,
        validate_security_context_bytes,
    )

    component_id = job.get("component_id")
    declared = job.get("security_context_projections", [])
    if not isinstance(declared, list):
        raise ControllerError("stride analyzer security-context projections must be an array")
    by_id = {row.get("context_id"): row for row in declared if isinstance(row, dict)}
    if len(by_id) != len(declared):
        raise ControllerError("stride analyzer security-context projections contain duplicate routes")
    manifest = _load_json_object(
        _resolve_artifact_path(output_root, ".stride-dispatch-manifest.json"),
        contract="stride-dispatch-manifest-v2",
    )
    if not declared and not manifest.get("components"):
        return []
    manifest_components = {
        row.get("component_id"): row for row in manifest.get("components", []) if isinstance(row, dict)
    }
    component = manifest_components.get(component_id)
    if not isinstance(component, dict):
        raise ControllerError("stride analyzer security-context projection references an unknown component")
    expected_by_id = {
        context_id: projection
        for context_id, projection in component_security_context_projections(output_root, component).items()
        if projection is not None
    }
    expected_ids = set(expected_by_id)
    if set(by_id) != expected_ids:
        raise ControllerError("stride analyzer security-context routes do not match current component sources")
    validated: list[dict[str, Any]] = []
    for context_id, row in by_id.items():
        filename = (
            SECURITY_CONTEXT_SPECS[context_id][2]
            if context_id in SECURITY_CONTEXT_SPECS
            else INLINE_SECURITY_CONTEXT_SPECS[context_id][1]
        )
        expected_path = f".dispatch-context/{component_id}/{filename}"
        if row.get("artifact_path") != expected_path or expected_path not in job.get("input_artifacts", []):
            raise ControllerError("stride analyzer security-context projection path is invalid")
        path = _resolve_artifact_path(output_root, expected_path)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ControllerError(f"cannot read component security-context projection: {exc}") from exc
        try:
            value = validate_security_context_bytes(
                payload,
                expected_component_id=component_id,
                expected_context_id=context_id,
                expected_sha256=row.get("sha256"),
            )
        except Exception as exc:
            raise ControllerError(f"component security-context validation failed: {exc}") from exc
        if value != expected_by_id[context_id][0]:
            raise ControllerError("component security-context projection is stale for its source index")
        matching = [receipt for receipt in artifact_receipts if receipt.get("artifact_path") == expected_path]
        expected_receipt = {
            "schema_version": 1,
            "artifact_path": expected_path,
            "schema_id": "schemas/stride-component-security-context.schema.json#v1",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "record_count": len(value["records"]),
            "validation_status": "valid",
        }
        if len(matching) != 1 or matching[0] != expected_receipt:
            raise ControllerError("stride analyzer security-context projection receipt is stale")
        validated.append(value)
    return validated


def _validate_stride_component_context_plan(
    output_root: Path,
    job: dict[str, Any],
    artifact_receipts: list[dict[str, Any]],
    stride_profile: Any,
) -> None:
    """Bind duplicated dispatch labels to the receipted component plan."""
    component_id = job.get("component_id")
    relative = job.get("context_plan_path")
    expected = f".dispatch-context/{component_id}/context-plan.json"
    if relative != expected or relative not in job.get("input_artifacts", []):
        raise ControllerError("stride analyzer component context plan does not match its component id")
    path = _resolve_artifact_path(output_root, relative)
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / "stride-component-context-plan.schema.json",
        contract="stride-component-context-plan-v1",
    )
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != job.get("context_plan_sha256"):
        raise ControllerError("stride analyzer component context plan hash is stale")
    matching_receipts = [row for row in artifact_receipts if row.get("artifact_path") == relative]
    if len(matching_receipts) != 1:
        raise ControllerError("stride analyzer component context plan requires one exact-byte receipt")
    plan_receipt = matching_receipts[0]
    bundle_path = f".dispatch-context/{component_id}/evidence-bundle.json"
    bundle = _load_json_object(_resolve_artifact_path(output_root, bundle_path), contract="stride-evidence-bundle-v1")
    repository_projection = _validate_stride_component_repository_roots(
        output_root,
        job,
        bundle,
        artifact_receipts,
    )
    architecture_context = _validate_stride_component_architecture_context(output_root, job, artifact_receipts)
    business_context = _validate_stride_component_business_context(output_root, job, artifact_receipts)
    llm_policy = _validate_stride_component_llm_policy(output_root, job, artifact_receipts)
    security_contexts = _validate_stride_component_security_contexts(output_root, job, artifact_receipts)
    expected_input_count = (
        2
        + int(repository_projection is not None)
        + int(architecture_context is not None)
        + int(business_context is not None)
        + int(llm_policy is not None)
        + len(security_contexts)
    )
    if (
        plan_receipt.get("schema_id") != "schemas/stride-component-context-plan.schema.json#v1"
        or plan_receipt.get("sha256") != job.get("context_plan_sha256")
        or plan_receipt.get("record_count") != expected_input_count
    ):
        raise ControllerError("stride analyzer component context plan receipt is stale")
    if value["component_id"] != component_id:
        raise ControllerError("stride analyzer component context plan contains another component")
    analysis = value["analysis"]
    expected_analysis = {
        "depth": job.get("analysis_depth"),
        "max_turns": job.get("max_turns"),
        "sampling_required": job.get("sampling_required"),
        "file_count": job.get("file_count"),
        "estimated_threat_count": job.get("estimated_threat_count"),
        "stride_profile": stride_profile,
    }
    if analysis != expected_analysis or value["lens_ids"] != job.get("lens_ids"):
        raise ControllerError("stride analyzer job metadata drifted from its component context plan")
    inputs = {row["context_id"]: row for row in value["inputs"]}
    expected_context_ids = {"controls.component_evidence", "threats.component_taxonomy"}
    if architecture_context is not None:
        expected_context_ids.add("architecture.component_context")
    if business_context is not None:
        expected_context_ids.add("business.component_context")
    if llm_policy is not None:
        expected_context_ids.add("policy.llm_policy")
    if repository_projection is not None:
        expected_context_ids.add("threats.related_repositories")
    expected_context_ids.update(value["context_id"] for value in security_contexts)
    if len(inputs) != len(value["inputs"]) or set(inputs) != expected_context_ids:
        raise ControllerError("stride analyzer component context plan has duplicate or missing inputs")
    if inputs["controls.component_evidence"] != {
        "context_id": "controls.component_evidence",
        "artifact_path": bundle_path,
        "sha256": job.get("evidence_bundle_sha256"),
    }:
        raise ControllerError("stride analyzer evidence bundle drifted from its component context plan")
    if architecture_context is not None and inputs["architecture.component_context"] != {
        "context_id": "architecture.component_context",
        "artifact_path": job.get("architecture_context_path"),
        "sha256": job.get("architecture_context_sha256"),
    }:
        raise ControllerError("stride analyzer architecture context drifted from its component context plan")
    if business_context is not None and inputs["business.component_context"] != {
        "context_id": "business.component_context",
        "artifact_path": job.get("business_context_path"),
        "sha256": job.get("business_context_sha256"),
    }:
        raise ControllerError("stride analyzer business context drifted from its component context plan")
    if llm_policy is not None and inputs["policy.llm_policy"] != {
        "context_id": "policy.llm_policy",
        "artifact_path": job.get("llm_policy_path"),
        "sha256": job.get("llm_policy_sha256"),
    }:
        raise ControllerError("stride analyzer llm policy drifted from its component context plan")
    if inputs["threats.component_taxonomy"] != {
        "context_id": "threats.component_taxonomy",
        "artifact_path": job.get("taxonomy_slice_path"),
        "sha256": job.get("taxonomy_slice_sha256"),
    }:
        raise ControllerError("stride analyzer taxonomy drifted from its component context plan")
    if repository_projection is not None and inputs["threats.related_repositories"] != {
        "context_id": "threats.related_repositories",
        "artifact_path": job.get("repository_projection_path"),
        "sha256": job.get("repository_projection_sha256"),
    }:
        raise ControllerError("stride analyzer related repositories drifted from its component context plan")
    for projection in job.get("security_context_projections", []):
        context_id = projection["context_id"]
        if inputs.get(context_id) != projection:
            raise ControllerError("stride analyzer security context drifted from its component context plan")
    for row in inputs.values():
        artifact = _resolve_artifact_path(output_root, row["artifact_path"])
        try:
            actual_sha256 = hashlib.sha256(artifact.read_bytes()).hexdigest()
        except OSError as exc:
            raise ControllerError(f"cannot read component context input {row['artifact_path']!r}: {exc}") from exc
        if actual_sha256 != row["sha256"]:
            raise ControllerError(f"component context input changed after admission: {row['artifact_path']}")
    manifest_path = _resolve_artifact_path(output_root, ".stride-dispatch-manifest.json")
    try:
        manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ControllerError(f"cannot read source dispatch manifest for component context plan: {exc}") from exc
    if manifest_sha256 != value["source_manifest_sha256"]:
        raise ControllerError("stride analyzer component context plan is stale for the dispatch manifest")


def _checked_next_boundary(command: str) -> str:
    """Return the successor boundary command, rejecting an unknown name.

    The caller must not derive the successor from the depth-dependent shape of
    the run: quick depth skips actor discovery, so the boundary after recon is
    ``context-v2-post-architecture`` there and ``context-v2-post-actors``
    otherwise. Only the controller knows which job it just dispatched, so it
    names the successor and the caller invokes it verbatim.
    """
    if command not in _SEMANTIC_RETURN_COMMANDS:
        raise ControllerError(f"unknown successor boundary: {command!r}")
    return command


def _context_v2_dispatch(
    output_dir: Path,
    cfg: dict[str, Any],
    *,
    role: str,
    job_id: str,
    next_boundary: str,
    input_artifacts: list[str],
    output_artifacts: list[str],
    decision_keys: list[str],
    receipts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return one closed-registry semantic boundary action."""
    action = {
        **_context_v2_common(output_dir, cfg),
        "action": "dispatch_agent",
        "semantic_role": role,
        "next_boundary": _checked_next_boundary(next_boundary),
        "dispatch_jobs": [
            {
                "schema_version": 1,
                "job_id": job_id,
                "semantic_role": role,
                **_context_v2_job_metadata(cfg, role),
                "input_artifacts": input_artifacts,
                "output_artifacts": output_artifacts,
                "unresolved_decision_keys": decision_keys,
            }
        ],
        "artifact_receipts": receipts,
        "unresolved_decision_keys": decision_keys,
    }
    try:
        already_issued = context_routing.action_already_issued(action, output_dir)
    except context_routing.ContextRoutingError as exc:
        raise ControllerError(f"context-v2 dispatch replay rejected: {exc}") from exc
    if not already_issued:
        _prepare_context_v2_dispatch_outputs(output_dir, action["dispatch_jobs"])
    return _validate_action(action)


def _validated_json_receipt(
    output_dir: Path,
    artifact_path: str,
    *,
    schema_id: str,
    record_count: int,
) -> dict[str, Any]:
    return create_artifact_receipt(
        output_dir,
        artifact_path,
        schema_id=schema_id,
        record_count=record_count,
    )


def _validated_text_receipt(
    output_dir: Path,
    artifact_path: str,
    *,
    schema_id: str,
    record_count: int,
    max_bytes: int,
) -> dict[str, Any]:
    """Receipt exact bytes for a bounded non-JSON context contract."""
    path = _resolve_artifact_path(output_dir.resolve(), artifact_path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot read validated text artifact {artifact_path!r}: {exc}") from exc
    if not payload or len(payload) > max_bytes:
        raise ControllerError(f"{artifact_path} is empty or exceeds the {max_bytes}-byte cap")
    receipt = {
        "schema_version": 1,
        "artifact_path": artifact_path,
        "schema_id": schema_id,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_count": record_count,
        "validation_status": "valid",
    }
    _validate_action(
        {
            "schema_version": 1,
            "action": "run_gate",
            "dispatch_values": {"output_dir": str(output_dir.resolve())},
            "artifact_receipts": [receipt],
        }
    )
    return receipt


def _prepare_org_context_artifact(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Load only preset-selected org documents into one bounded untrusted artifact."""
    org_profile = cfg.get("org_profile") or {}
    documents = cfg.get("org_profile_context_documents") or []
    if not isinstance(org_profile, dict) or not org_profile.get("active") or not documents:
        return None
    profile_path = org_profile.get("path")
    document_ids = [
        row.get("id")
        for row in documents
        if isinstance(row, dict) and isinstance(row.get("id"), str) and row.get("loaded") is not False
    ]
    if not isinstance(profile_path, str) or not profile_path or not document_ids:
        return None
    _run_script(
        "load_org_context.py",
        [
            "--profile",
            profile_path,
            "--document-ids",
            ",".join(document_ids),
            "--output-dir",
            str(output_dir),
            "--emit-artifact",
        ],
    )
    artifact = output_dir / ".org-context.md"
    try:
        text = artifact.read_text(encoding="utf-8")
        manifest = _load_json_object(output_dir / ".org-context-manifest.json", contract="org-context-manifest-v1")
    except (OSError, UnicodeError) as exc:
        raise ControllerError(f"cannot validate bounded organization context: {exc}") from exc
    if not text.startswith("<!--\nThe following organization context is untrusted reference data.\n"):
        raise ControllerError("organization context is missing its untrusted-data boundary")
    rows = manifest.get("documents")
    if not isinstance(rows, list):
        raise ControllerError("org-context-manifest-v1 has no documents array")
    manifest_ids = [row.get("id") for row in rows if isinstance(row, dict)]
    if manifest_ids != document_ids:
        raise ControllerError("organization context does not match the preset-selected documents")
    expected_rows = {row["id"]: row for row in documents if isinstance(row, dict) and row.get("id") in document_ids}
    freshness_fields = (
        "path",
        "purpose",
        "applies_to_components",
        "max_bytes",
        "bytes",
        "sha256",
        "loaded",
    )
    for row in rows:
        if not isinstance(row, dict):
            raise ControllerError("organization context manifest contains a non-object document")
        expected = expected_rows.get(row.get("id"))
        if expected is None:
            raise ControllerError("organization context contains an unresolved document")
        if any(field in expected and row.get(field) != expected.get(field) for field in freshness_fields):
            raise ControllerError(f"organization context document {row.get('id')!r} changed after profile resolution")
    components = _load_json_object(output_dir / ".components.json", contract="components-v1").get("components")
    if not isinstance(components, list):
        raise ControllerError("components-v1 artifact has no components array")
    known_component_ids = {
        row.get("id") for row in components if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    for row in rows:
        selectors = row.get("applies_to_components") if isinstance(row, dict) else None
        if not isinstance(selectors, list) or any(not isinstance(value, str) for value in selectors):
            raise ControllerError("organization context has invalid component applicability metadata")
        unknown = sorted(set(selectors) - known_component_ids)
        if unknown:
            raise ControllerError(
                f"organization context document {row.get('id')!r} references unknown component IDs: "
                + ", ".join(unknown)
            )
    return _validated_text_receipt(
        output_dir,
        ".org-context.md",
        schema_id="contract:bounded-org-context-markdown-v1",
        record_count=len(rows),
        max_bytes=MAX_ORG_CONTEXT_BYTES,
    )


def _write_merge_review_context(output_dir: Path, candidates: dict[str, Any], source_payload: bytes) -> dict[str, Any]:
    """Project the full merge state into one bounded semantic-review artifact."""
    from _atomic_io import atomic_write_text

    groups = candidates.get("candidate_groups")
    if not isinstance(groups, list) or not groups:
        raise ControllerError("merge review context requires at least one candidate group")
    if len(groups) > 64:
        raise ControllerError("merge-candidates-v1 exceeds the 64-group semantic admission cap")
    for group in groups:
        members = group.get("members") if isinstance(group, dict) else None
        if not isinstance(members, list) or len(members) > 256:
            group_id = group.get("group_id") if isinstance(group, dict) else "unknown"
            raise ControllerError(f"merge candidate group {group_id!r} exceeds the 256-member admission cap")
        if group.get("member_count") != len(members):
            raise ControllerError(f"merge candidate group {group.get('group_id')!r} has a stale member count")

    payload = {
        "schema_version": 1,
        "source_artifact": ".merge-candidates.json",
        "source_sha256": hashlib.sha256(source_payload).hexdigest(),
        "candidate_group_count": len(groups),
        "candidate_groups": groups,
        "limits": {"serialized_bytes": 1, "estimated_tokens": 1},
    }
    previous: tuple[int, int] | None = None
    rendered = b""
    for _ in range(10):
        rendered = _canonical_json_bytes(payload) + b"\n"
        current = (len(rendered), (len(rendered) + 3) // 4)
        payload["limits"] = {"serialized_bytes": current[0], "estimated_tokens": current[1]}
        if current == previous:
            rendered = _canonical_json_bytes(payload) + b"\n"
            break
        previous = current
    else:
        raise ControllerError("merge review context size metadata did not converge")
    if len(rendered) > 262_144 or (len(rendered) + 3) // 4 > 65_536:
        raise ControllerError("merge review context exceeds the 262144-byte semantic admission cap")

    path = output_dir / ".merge-context" / "candidates.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, rendered.decode("utf-8"))
    return payload


def _context_v2_run_posture_emitters(output_dir: Path, cfg: dict[str, Any], receipts: list[str]) -> None:
    """Run the existing passive Phase-10 emitters without returning to a model."""
    repo_root = str(cfg.get("repo_root") or output_dir)
    _best_effort_script(
        output_dir,
        "emit_dep_update_activity.py",
        ["--repo-root", repo_root, "--output-dir", str(output_dir)],
        receipts,
    )
    for name in ("emit_sca_practice.py", "emit_known_bad_libs.py"):
        _best_effort_script(
            output_dir,
            name,
            ["--repo-root", repo_root, "--output-dir", str(output_dir), "--asset-tier", "T2"],
            receipts,
        )


# Filesystem markers that make a config/IaC scan worth an agent. Fixed and
# plugin-owned: repository content selects the boolean, never a path or command.
_IAC_SURFACE_GLOBS = (
    "Dockerfile",
    "*.dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
    "renovate.json5",
    ".renovaterc",
    ".npmrc",
    ".yarnrc.yml",
)
_CONFIG_SCAN_STUB = '{"parse_error": "skipped: no IaC surface detected", "findings": []}\n'


# Directories that never carry a deployable IaC surface but dominate a
# recursive walk on a real repository.
_IAC_WALK_PRUNE = {".git", "node_modules", ".venv", "venv", "dist", "build", ".appsec-cache"}
_IAC_WALK_MAX_ENTRIES = 200_000


def _has_iac_surface(repo_root: Path) -> bool:
    """Deterministic IaC-surface pre-check for the Phase-2.5 selection.

    One bounded walk matching every pattern at once. Thirteen separate
    recursive globs re-walk the tree per pattern and are the documented
    cold-cache hazard on a monorepo. Hitting the entry cap answers "true" so an
    unwalked remainder can never silently drop the config scan.
    """
    relative_globs = [pattern for pattern in _IAC_SURFACE_GLOBS if "/" in pattern]
    name_globs = [pattern for pattern in _IAC_SURFACE_GLOBS if "/" not in pattern]
    visited = 0
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in _IAC_WALK_PRUNE]
        visited += len(filenames)
        if visited > _IAC_WALK_MAX_ENTRIES:
            return True
        for filename in filenames:
            if any(fnmatch.fnmatch(filename, pattern) for pattern in name_globs):
                return True
            relative = (Path(dirpath) / filename).relative_to(repo_root).as_posix()
            if any(fnmatch.fnmatch(relative, f"*{pattern}") for pattern in relative_globs):
                return True
    return False


def _context_skip(output_dir: Path, cfg: dict[str, Any]) -> bool:
    """Reuse a prior context file only on an incremental run newer than HEAD.

    A full or rebuild run always re-resolves context: an existing
    `.threat-modeling-context.md` survives full cleanup, so treating mere
    presence as a cache hit would silently reuse stale policy and prior-finding
    data on every rerun.
    """
    if not cfg.get("incremental"):
        return False
    context_file = output_dir / ".threat-modeling-context.md"
    try:
        context_epoch = context_file.stat().st_mtime
        _validate_threat_modeling_context(context_file)
    except (OSError, ControllerError):
        return False
    head = subprocess.run(
        ["git", "-C", str(cfg.get("repo_root") or output_dir), "log", "-1", "--format=%ct"],
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        head_epoch = float(head.stdout.strip())
    except ValueError:
        return False
    return context_epoch > head_epoch > 0


def _recon_skip(output_dir: Path, cfg: dict[str, Any]) -> bool:
    """Reuse a prior recon summary only when the fingerprint contract allows it."""
    if not (output_dir / ".recon-summary.md").is_file() or not (output_dir / ".recon-signals.json").is_file():
        return False
    try:
        _validate_recon_summary(output_dir / ".recon-summary.md", Path(str(cfg.get("repo_root") or output_dir)))
        _validate_recon_signals(
            output_dir / ".recon-signals.json",
            Path(str(cfg.get("repo_root") or output_dir)),
        )
    except ControllerError:
        return False
    incremental = bool(cfg.get("incremental"))
    if not incremental and not cfg.get("recon_reuse_eligible"):
        return False
    args = [
        "check-fingerprint",
        "--output-dir",
        str(output_dir),
        "--repo-root",
        str(cfg.get("repo_root") or output_dir),
    ]
    if not incremental:
        # An auto-upgraded full run has no incremental git-diff back-stop, so
        # the tree must be git-provably unchanged before recon may be reused.
        args.append("--require-clean-tree")
    try:
        _run_script("baseline_state.py", args)
    except ControllerError:
        return False
    return True


def context_v2_begin(output_dir: Path) -> dict[str, Any]:
    """Run the Phase-1/2 pre-passes and return one bounded recon wave."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    try:
        context_routing.reset_plan(output_dir)
    except context_routing.ContextRoutingError as exc:
        raise ControllerError(f"cannot reset context routing effective plan: {exc}") from exc
    repo_root = Path(str(cfg.get("repo_root") or output_dir))
    receipts: list[str] = []
    structured: list[dict[str, Any]] = []

    # These optional late-stage outputs may not get a producer in this run.
    # Clear them at the fresh context-v2 entry boundary so a skipped verifier,
    # empty threat set, or currently inactive mitigation branch cannot consume
    # a schema-valid sidecar retained from an earlier full run.
    _prepare_context_v2_dispatch_outputs(
        output_dir,
        [
            {
                "input_artifacts": [],
                "output_artifacts": [
                    ".evidence-verification.json",
                    ".mitigation-overrides.json",
                    ".tier-root-causes.json",
                ],
            }
        ],
    )

    recon_skip = _recon_skip(output_dir, cfg)
    context_skip = _context_skip(output_dir, cfg)
    has_iac = _has_iac_surface(repo_root)
    if not has_iac:
        from _atomic_io import atomic_write_text

        # Downstream consumers read a contracted shape either way; the stub is
        # what "no IaC surface" looks like, not a missing artifact.
        atomic_write_text(output_dir / ".config-scan-findings.json", _CONFIG_SCAN_STUB)
        receipts.append("config scan skipped: no IaC surface")

    if not recon_skip:
        pattern_args = ["all", "--repo-root", str(repo_root)]
        if cfg.get("scan_manifest"):
            pattern_args.extend(["--manifest-file", str(output_dir / ".scan-manifest.txt")])
        try:
            completed = _run_script("recon_patterns.py", pattern_args)
            (output_dir / ".recon-patterns.json").write_text(completed.stdout, encoding="utf-8")
            patterns = _validate_json_artifact(
                output_dir / ".recon-patterns.json",
                PLUGIN_ROOT / "schemas" / "recon-patterns.schema.json",
                contract="recon-patterns-v1",
            )
            structured.append(
                _validated_json_receipt(
                    output_dir,
                    ".recon-patterns.json",
                    schema_id="schemas/recon-patterns.schema.json#v1",
                    record_count=len(patterns["categories"]),
                )
            )
        except (ControllerError, OSError) as exc:
            # The recon-scanner falls back to LLM grep for these categories.
            # An optional producer failure must not leave bytes that routing
            # can mistake for a validated delivery.
            (output_dir / ".recon-patterns.json").unlink(missing_ok=True)
            receipts.append("recon_patterns.py: best-effort failure")
            _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")
        # Without --output the script defaults into the scanned repository.
        fragments = output_dir / ".fragments"
        fragments.mkdir(parents=True, exist_ok=True)
        _best_effort_script(
            output_dir,
            "extract_data_relations.py",
            [str(repo_root), "--output", str(fragments / "data-relations.json"), "--quiet"],
            receipts,
        )

    if not context_skip:
        _run_script(
            "build_threat_modeling_context.py",
            [
                "--repo-root",
                str(repo_root),
                "--output-dir",
                str(output_dir),
                "--plugin-root",
                str(PLUGIN_ROOT),
            ],
        )
        context_path = output_dir / ".threat-modeling-context.md"
        _validate_threat_modeling_context(context_path)
        structured.append(
            _validated_text_receipt(
                output_dir,
                ".threat-modeling-context.md",
                schema_id="contract:threat-modeling-context-markdown-v1",
                record_count=1,
                max_bytes=MAX_THREAT_MODELING_CONTEXT_BYTES,
            )
        )
        receipts.append("project context built deterministically")
    else:
        receipts.append("context resolution reused from cache")

    jobs: list[dict[str, Any]] = []
    if not recon_skip:
        recon_inputs = [".skill-config.json"]
        if (output_dir / ".recon-patterns.json").is_file():
            recon_inputs.append(".recon-patterns.json")
        jobs.append(
            {
                "schema_version": 1,
                "job_id": "phase2-recon",
                "semantic_role": "recon_scanner",
                **_context_v2_job_metadata(cfg, "recon_scanner"),
                "input_artifacts": recon_inputs,
                "output_artifacts": [".recon-summary.md", ".recon-signals.json"],
                "unresolved_decision_keys": [],
            }
        )
    else:
        receipts.append("recon summary reused: fingerprint unchanged")
    _append_event(
        output_dir,
        "CONTEXT_V2_RECON_WAVE",
        f"jobs={len(jobs)} context_source=deterministic recon_skip={str(recon_skip).lower()} "
        f"has_iac_surface={str(has_iac).lower()}",
    )
    if not jobs:
        return _context_v2_after_recon(output_dir, cfg, receipts)
    _prepare_context_v2_dispatch_outputs(output_dir, jobs)
    return _validate_action(
        {
            **_context_v2_common(output_dir, cfg),
            "action": "dispatch_parallel",
            "next_boundary": _checked_next_boundary("context-v2-post-recon"),
            "dispatch_jobs": jobs,
            "artifact_receipts": structured,
            "receipts": ["Context-v2 Phase-1/2 pre-passes complete", *receipts],
        }
    )


def _recon_producer_retry(
    output_dir: Path,
    cfg: dict[str, Any],
    artifact: str,
    exc: ProducerContractError,
) -> dict[str, Any] | None:
    """Redispatch the recon producer once with the errors it has to fix.

    Returns None when the retry budget is spent, which restores the terminal
    abort. The job id carries the attempt so the effective plan sees a new
    action rather than a replay of the one already recorded.
    """
    attempt = _claim_producer_retry(output_dir, f"recon_scanner:{artifact}")
    if attempt is None:
        return None
    brief = _write_producer_repair_brief(output_dir, artifact, exc.errors)
    _append_event(
        output_dir,
        "PRODUCER_CONTRACT_RETRY",
        f"role=recon_scanner artifact={artifact} attempt={attempt} errors={len(exc.errors)} reason={exc}",
        level="WARN",
    )
    # The summary already passed its own gate; naming it an input both keeps the
    # producer's earlier observations available and protects it from the output
    # clearing below. Only the rejected artifact is rewritten.
    inputs = [".skill-config.json", ".recon-summary.md", brief]
    if (output_dir / ".recon-patterns.json").is_file():
        inputs.append(".recon-patterns.json")
    jobs = [
        {
            "schema_version": 1,
            "job_id": f"phase2-recon:attempt-{attempt}",
            "semantic_role": "recon_scanner",
            **_context_v2_job_metadata(cfg, "recon_scanner"),
            "input_artifacts": inputs,
            "output_artifacts": [artifact],
            "unresolved_decision_keys": [],
        }
    ]
    action = {
        **_context_v2_common(output_dir, cfg),
        "action": "dispatch_parallel",
        "next_boundary": _checked_next_boundary("context-v2-post-recon"),
        "dispatch_jobs": jobs,
        "artifact_receipts": [],
        "receipts": [f"recon producer redispatched to repair {artifact} (attempt {attempt})"],
    }
    if not context_routing.action_already_issued(action, output_dir):
        _prepare_context_v2_dispatch_outputs(output_dir, jobs)
    return _validate_action(action)


def _context_v2_after_recon(output_dir: Path, cfg: dict[str, Any], receipts: list[str]) -> dict[str, Any]:
    """Run Phases 2.5b, 2.6, and 2.7 until the next semantic boundary."""
    repo_root = str(cfg.get("repo_root") or output_dir)
    depth = str(cfg.get("assessment_depth") or "standard")

    if not (output_dir / ".recon-summary.md").is_file():
        raise ControllerError("context-v2 recon wave did not produce .recon-summary.md")
    if not (output_dir / ".threat-modeling-context.md").is_file():
        raise ControllerError("context-v2 context wave did not produce .threat-modeling-context.md")
    context_path = output_dir / ".threat-modeling-context.md"
    repaired_headings = _repair_missing_threat_modeling_context_headings(context_path)
    if repaired_headings:
        repaired_names = ", ".join(repaired_headings)
        _append_event(output_dir, "CONTEXT_STRUCTURE_REPAIRED", f"inserted={repaired_names}", level="WARN")
        receipts.append(f"context structure normalized: inserted {repaired_names}")
    _validate_threat_modeling_context(context_path)
    recon_summary_path = output_dir / ".recon-summary.md"
    normalized_key_file_lines = recon_summary_contract.normalize_key_file_references(
        recon_summary_path,
        Path(repo_root),
    )
    if normalized_key_file_lines:
        _append_event(
            output_dir,
            "RECON_KEY_FILES_NORMALIZED",
            f"lines={normalized_key_file_lines}",
            level="WARN",
        )
        receipts.append(f"recon Key files normalized: lines={normalized_key_file_lines}")
    _validate_recon_summary(recon_summary_path, Path(repo_root))
    recon_line_count = len(recon_summary_path.read_text(encoding="utf-8").splitlines())
    if recon_line_count > TARGET_RECON_SUMMARY_LINES:
        _append_event(
            output_dir,
            "RECON_SUMMARY_TARGET_EXCEEDED",
            f"lines={recon_line_count} target={TARGET_RECON_SUMMARY_LINES}",
            level="WARN",
        )
    try:
        _validate_recon_signals(output_dir / ".recon-signals.json", Path(repo_root))
    except ProducerContractError as exc:
        retry = _recon_producer_retry(output_dir, cfg, ".recon-signals.json", exc)
        if retry is not None:
            return retry
        raise

    # Phase 2.5b — run the catalog scan deterministically before schema
    # validation. Context-v2 does not dispatch a model for this mechanical
    # producer. Clear any prior bytes first so a failed fresh scan cannot admit
    # a stale but shape-valid enrichment artifact.
    config_findings = output_dir / ".config-scan-findings.json"
    if _has_iac_surface(Path(repo_root)):
        config_findings.unlink(missing_ok=True)
        config_scan_valid = _best_effort_script(
            output_dir,
            "config_iac_scanner.py",
            [
                "--repo-root",
                repo_root,
                "--output",
                str(config_findings),
                "--assessment-depth",
                depth,
            ],
            receipts,
        )
        if config_scan_valid:
            receipts.append("config scan produced deterministically from the complete catalog")
    if config_findings.is_file():
        _best_effort_script(output_dir, "normalize_config_scan.py", [str(config_findings)], receipts)
        config_valid = _best_effort_script(
            output_dir,
            "validate_intermediate.py",
            ["config_scan_findings", str(config_findings)],
            receipts,
        )
        if not config_valid:
            from _atomic_io import atomic_write_text

            atomic_write_text(config_findings, _CONFIG_SCAN_STUB)
            receipts.append("invalid config scan replaced with no-surface stub")

    # Phase 2.5 Step 1c — cross-repository register.
    register_args = [
        "--repo-root",
        repo_root,
        "--recon-summary",
        str(output_dir / ".recon-summary.md"),
        "--output",
        str(output_dir / ".cross-repo-register.json"),
    ]
    declared = output_dir / ".related-repos-loaded.json"
    if declared.is_file():
        register_args.extend(["--declared-json", str(declared)])
    _best_effort_script(output_dir, "build_cross_repo_register.py", register_args, receipts)

    # Phase 2.6 — deterministic architecture-coverage pre-pass. Always runs so
    # "always-on" rules still emit not_applicable rows on an unmatched repo.
    _run_script(
        "route_inventory.py",
        ["--repo-root", repo_root, "--output-dir", str(output_dir)],
    )
    _run_script(
        "build_architecture_analysis_context.py",
        ["--output-dir", str(output_dir)],
    )
    if depth == "thorough":
        _best_effort_script(
            output_dir,
            "database_privilege_separation.py",
            ["--repo-root", repo_root, "--output-dir", str(output_dir), "--assessment-depth", "thorough"],
            receipts,
        )
    _best_effort_script(
        output_dir,
        "architecture_coverage_checks.py",
        ["--repo-root", repo_root, "--output-dir", str(output_dir), "--assessment-depth", depth],
        receipts,
    )

    # Phase 2.7 Step 1 — static actor layers. Never skipped; quick depth drops
    # only the LLM discovery steps.
    resolve_args = _actor_resolver_args(output_dir, cfg)
    if depth == "quick":
        resolve_args.append("--quick")
    _run_script("resolve_actors.py", resolve_args)
    _run_script(
        "validate_intermediate.py",
        ["actors_resolved", str(output_dir / ".actors-resolved.json")],
    )

    if depth == "quick" or not _actor_discovery_enabled(output_dir):
        return _context_v2_dispatch_architecture(output_dir, cfg, receipts)

    try:
        cache_key = _run_script(
            "actor_discovery_cache.py",
            ["compute", "--output-dir", str(output_dir), "--plugin-root", str(PLUGIN_ROOT)],
        ).stdout.strip()
        cached = _run_script(
            "actor_discovery_cache.py",
            [
                "check",
                "--discovery-output",
                str(output_dir / ".actors-discovered.json"),
                "--expected-key",
                cache_key,
            ],
        ).stdout.strip()
    except ControllerError as exc:
        receipts.append("actor_discovery_cache.py: best-effort failure")
        _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")
        return _context_v2_dispatch_architecture(output_dir, cfg, receipts)

    if cached == "hit" and not cfg.get("refresh_actor_discovery"):
        receipts.append("actor discovery reused from cache")
        return _context_v2_dispatch_architecture(output_dir, cfg, receipts)

    return _context_v2_dispatch(
        output_dir,
        cfg,
        role="actor_discoverer",
        job_id="phase2_7-actors",
        next_boundary="context-v2-post-actors",
        input_artifacts=[
            ".actors-merged-static.json",
            ".dispatch-context/architecture/recon-summary-context.json",
            ".recon-signals.json",
        ],
        output_artifacts=[".actors-discovered.json"],
        decision_keys=["discovered_actor_set"],
        receipts=_context_v2_actor_input_receipts(output_dir),
    )


def _record_count(path: Path, key: str) -> int:
    """Length of a contracted array, for a receipt that has already validated."""
    try:
        value = json.loads(path.read_text(encoding="utf-8")).get(key)
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise ControllerError(f"cannot read record count from {path.name}: {exc}") from exc
    if not isinstance(value, list):
        raise ControllerError(f"{path.name} has no {key!r} array")
    return len(value)


def _actor_resolver_args(output_dir: Path, cfg: dict[str, Any]) -> list[str]:
    args = [
        "--plugin-root",
        str(PLUGIN_ROOT),
        "--repo-root",
        str(cfg.get("repo_root") or output_dir),
        "--output-dir",
        str(output_dir),
        "--signals",
        str(output_dir / ".recon-signals.json"),
    ]
    org_profile = output_dir / ".org-profile-effective.json"
    if org_profile.is_file():
        args.extend(["--org-profile-effective", str(org_profile)])
    return args


def _actor_discovery_enabled(output_dir: Path) -> bool:
    """Repository configuration may disable discovery; absence never enables it."""
    try:
        resolved = json.loads((output_dir / ".actors-resolved.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(resolved.get("discovery_enabled"))


def _validated_projection_receipt(
    output_dir: Path,
    artifact_path: str,
    *,
    schema_id: str,
    record_key: str,
    source_artifact: str,
    projector: Any | None = None,
) -> dict[str, Any]:
    """Bind a bounded projection to its exact bytes and deterministic source."""
    schema_relative = schema_id.partition("#")[0]
    projected = _validate_json_artifact(
        output_dir / artifact_path,
        PLUGIN_ROOT / schema_relative,
        contract=schema_id,
    )
    source = projected.get("source")
    if not isinstance(source, dict) or source.get("artifact_path") != source_artifact:
        raise ControllerError(f"{artifact_path} names an unexpected source artifact")
    try:
        source_payload = (output_dir / source_artifact).read_bytes()
        source_sha256 = hashlib.sha256(source_payload).hexdigest()
    except OSError as exc:
        raise ControllerError(f"cannot re-hash projection source {source_artifact}: {exc}") from exc
    if source.get("sha256") != source_sha256:
        raise ControllerError(f"{artifact_path} is stale for {source_artifact}")
    if projector is not None:
        try:
            expected = projector(source_payload)
        except Exception as exc:
            raise ControllerError(f"cannot reconstruct deterministic projection {artifact_path}: {exc}") from exc
        if projected != expected:
            raise ControllerError(f"{artifact_path} differs from its deterministic projection")
    records = projected.get(record_key)
    if not isinstance(records, (list, dict)):
        raise ControllerError(f"{artifact_path} has no {record_key!r} records")
    return _validated_json_receipt(
        output_dir,
        artifact_path,
        schema_id=schema_id,
        record_count=len(records),
    )


def _context_v2_recon_projection_receipt(output_dir: Path) -> dict[str, Any]:
    from build_architecture_analysis_context import project_recon_summary  # noqa: PLC0415

    return _validated_projection_receipt(
        output_dir,
        ".dispatch-context/architecture/recon-summary-context.json",
        schema_id="schemas/recon-summary-context.schema.json#v1",
        record_key="sections",
        source_artifact=".recon-summary.md",
        projector=project_recon_summary,
    )


def _context_v2_route_projection_receipt(output_dir: Path) -> dict[str, Any]:
    from build_architecture_analysis_context import project_routes  # noqa: PLC0415

    return _validated_projection_receipt(
        output_dir,
        ".dispatch-context/architecture/route-context.json",
        schema_id="schemas/architecture-route-context.schema.json#v1",
        record_key="routes",
        source_artifact=".route-inventory.json",
        projector=project_routes,
    )


def _context_v2_actor_input_receipts(output_dir: Path) -> list[dict[str, Any]]:
    signals = _load_json_object(output_dir / ".recon-signals.json", contract="recon-signals-v2")
    signal_values = signals.get("signals")
    if not isinstance(signal_values, dict):
        raise ControllerError("recon-signals-v2 artifact has no signals object")
    return [
        _validated_json_receipt(
            output_dir,
            ".actors-merged-static.json",
            schema_id="schemas/actors-merged-static.schema.yaml#v1",
            record_count=_record_count(output_dir / ".actors-merged-static.json", "resolved_actors"),
        ),
        _context_v2_recon_projection_receipt(output_dir),
        _validated_json_receipt(
            output_dir,
            ".recon-signals.json",
            schema_id="schemas/recon-signals.schema.json#v2",
            record_count=len(signal_values),
        ),
    ]


def _context_v2_dispatch_architecture(output_dir: Path, cfg: dict[str, Any], receipts: list[str]) -> dict[str, Any]:
    structured = [
        _context_v2_recon_projection_receipt(output_dir),
        _context_v2_route_projection_receipt(output_dir),
        _validated_json_receipt(
            output_dir,
            ".actors-resolved.json",
            schema_id="schemas/actors-resolved.schema.yaml#v1",
            record_count=_record_count(output_dir / ".actors-resolved.json", "resolved_actors"),
        ),
    ]
    action = _context_v2_dispatch(
        output_dir,
        cfg,
        role="architecture_analyst",
        job_id="phase3-6-architecture",
        next_boundary="context-v2-post-architecture",
        input_artifacts=[
            ".dispatch-context/architecture/recon-summary-context.json",
            ".dispatch-context/architecture/route-context.json",
            ".actors-resolved.json",
        ],
        output_artifacts=[
            ".components.json",
            ".data-flows.json",
            ".assets.json",
            ".attack-surface-overrides.json",
        ],
        decision_keys=["component_inventory", "data_flows", "assets", "attack_surface"],
        receipts=structured,
    )
    action["receipts"] = ["Context-v2 Phases 2.5b-2.7 complete", *receipts]
    return _validate_action(action)


def context_v2_post_recon(output_dir: Path) -> dict[str, Any]:
    """Continue after the Phase-1/2 recon wave returns."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    return _context_v2_after_recon(output_dir, cfg, [])


def context_v2_post_actors(output_dir: Path) -> dict[str, Any]:
    """Validate discovery output and finalize the resolved actor set."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    receipts: list[str] = []
    discovered = output_dir / ".actors-discovered.json"
    # Recomputed rather than carried in a sidecar: none of the key's five
    # inputs change while the discoverer runs, so this is the same key the
    # dispatch decision used.
    try:
        cache_key = _run_script(
            "actor_discovery_cache.py",
            ["compute", "--output-dir", str(output_dir), "--plugin-root", str(PLUGIN_ROOT)],
        ).stdout.strip()
    except ControllerError:
        cache_key = ""
    try:
        _run_script("validate_intermediate.py", ["actors_discovered", str(discovered)])
    except ControllerError:
        # An invalid contract degrades to the static actor set rather than
        # letting unvalidated discovery reach the resolver.
        _best_effort_script(
            output_dir,
            "actor_discovery_cache.py",
            [
                "write-empty",
                "--output",
                str(discovered),
                "--cache-key",
                cache_key,
                "--rationale",
                "Actor discovery returned an invalid contract; static actor layers remain authoritative.",
            ],
            receipts,
        )
        receipts.append("actor discovery rejected: invalid contract")
    _run_script(
        "resolve_actors.py",
        [*_actor_resolver_args(output_dir, cfg), "--discovery-output", str(discovered)],
    )
    _run_script(
        "validate_intermediate.py",
        ["actors_resolved", str(output_dir / ".actors-resolved.json")],
    )
    return _context_v2_dispatch_architecture(output_dir, cfg, receipts)


def context_v2_post_architecture(output_dir: Path) -> dict[str, Any]:
    """Gate the Phase 3-6 artifacts and open the trust-boundary boundary."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    _gate_architecture_stage(output_dir, cfg, controller_owned_handoff=True)
    return _context_v2_dispatch(
        output_dir,
        cfg,
        role="trust_boundary_analyst",
        job_id="phase7-boundary",
        next_boundary="context-v2-post-boundary",
        input_artifacts=[".trust-boundary-assessment-input.json"],
        output_artifacts=[".trust-boundary-candidates.json"],
        decision_keys=["trust_boundary_candidates"],
        receipts=[
            _validated_json_receipt(
                output_dir,
                ".trust-boundary-assessment-input.json",
                schema_id="schemas/trust-boundary-assessment-input.schema.json#v1",
                record_count=_record_count(output_dir / ".trust-boundary-assessment-input.json", "components"),
            )
        ],
    )


def context_v2_post_boundary(output_dir: Path) -> dict[str, Any]:
    """Promote Phase-7 candidates and open the Phase-8 control boundary."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    _gate_trust_boundary_promotion(output_dir, cfg)
    _validate_threat_modeling_context(output_dir / ".threat-modeling-context.md")
    project_context_receipt = _validated_text_receipt(
        output_dir,
        ".threat-modeling-context.md",
        schema_id="contract:threat-modeling-context-markdown-v1",
        record_count=1,
        max_bytes=MAX_THREAT_MODELING_CONTEXT_BYTES,
    )
    org_context_receipt = _prepare_org_context_artifact(output_dir, cfg)
    inputs = [
        ".components.json",
        ".trust-boundaries.json",
        ".architecture-coverage.json",
        ".threat-modeling-context.md",
    ]
    receipts = [
        _validated_json_receipt(
            output_dir,
            ".trust-boundaries.json",
            schema_id="schemas/fragments/trust-boundaries.schema.json#v2",
            record_count=_record_count(output_dir / ".trust-boundaries.json", "trust_boundaries"),
        ),
        project_context_receipt,
    ]
    if org_context_receipt is not None:
        inputs.append(".org-context.md")
        receipts.append(org_context_receipt)
    return _context_v2_dispatch(
        output_dir,
        cfg,
        role="control_analyst",
        job_id="phase8-controls",
        next_boundary="context-v2-prepare-stride",
        input_artifacts=inputs,
        output_artifacts=[".security-controls.json", ".stride-analyst-context.json"],
        decision_keys=["security_controls", "stride_semantic_context"],
        receipts=receipts,
    )


def _context_v2_stride_wave_action(
    output_dir: Path,
    cfg: dict[str, Any],
    manifest: dict[str, Any],
    *,
    initialize: bool,
) -> dict[str, Any] | None:
    """Claim and admit exactly one persisted STRIDE wave.

    The wave helper owns attempt counts and retries. Returning every manifest
    component directly would bypass both the configured concurrency bound and
    the persisted two-attempt budget.
    """
    components = manifest.get("components")
    if manifest.get("context_version") != 2 or not isinstance(components, list) or not components:
        raise ControllerError("stride-dispatch-manifest-v2 has no selected components")
    by_id = {
        component.get("component_id"): component
        for component in components
        if isinstance(component, dict) and isinstance(component.get("component_id"), str)
    }
    if len(by_id) != len(components):
        raise ControllerError("stride-dispatch-manifest-v2 contains duplicate or invalid component IDs")
    manifest_path = _resolve_artifact_path(output_dir.resolve(), ".stride-dispatch-manifest.json")
    try:
        manifest_payload = manifest_path.read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot read stride-dispatch-manifest-v2 exact bytes: {exc}") from exc
    manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()

    if initialize:
        _run_script(
            "stride_dispatch_waves.py",
            [
                "init",
                str(output_dir),
                "--concurrency",
                str(cfg.get("stride_concurrency") or 5),
            ],
        )
    claimed = _run_script("stride_dispatch_waves.py", ["claim", str(output_dir)])
    try:
        claim_payload = json.loads(claimed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ControllerError(f"STRIDE wave claim returned invalid JSON: {exc}") from exc
    if not isinstance(claim_payload, dict):
        raise ControllerError("STRIDE wave claim must return a JSON object")
    status = claim_payload.get("status")
    if status == "complete":
        return None
    # ``in_flight`` carries the wave already issued, so a boundary that is
    # re-read answers with that dispatch instead of ending the run. The replay
    # guard below then recognizes the identical action and skips the side
    # effect that would delete what the first dispatch produced.
    if status not in {"claimed", "in_flight"} or (status == "in_flight" and "wave" not in claim_payload):
        raise ControllerError(f"STRIDE wave claim returned unsupported status: {status!r}")
    wave = claim_payload.get("wave")
    claimed_components = wave.get("components") if isinstance(wave, dict) else None
    if not isinstance(claimed_components, list) or not claimed_components:
        raise ControllerError("STRIDE wave claim has no component entries")
    claimed_attempts = wave.get("attempts") if isinstance(wave, dict) else None
    if not isinstance(claimed_attempts, dict):
        raise ControllerError("STRIDE wave claim has no attempt accounting")
    retry_reasons = wave.get("retry_reasons") if isinstance(wave, dict) else None
    if isinstance(retry_reasons, dict) and retry_reasons:
        details = "; ".join(
            f"{component_id}={reason}"
            for component_id, reason in sorted(retry_reasons.items())
            if isinstance(component_id, str) and isinstance(reason, str)
        )
        if details:
            _append_event(output_dir, "CONTEXT_V2_STRIDE_RETRY", details)

    repository_registry = output_dir / ".stride-repository-registry.json"
    run_llm_policy = _run_llm_policy(output_dir)

    jobs: list[dict[str, Any]] = []
    structured: list[dict[str, Any]] = []
    seen: set[str] = set()
    for claimed_component in claimed_components:
        claimed_id = claimed_component.get("component_id") if isinstance(claimed_component, dict) else None
        component = by_id.get(claimed_id)
        component_id = component.get("component_id") if isinstance(component, dict) else None
        bundle_path = component.get("evidence_bundle_path") if isinstance(component, dict) else None
        if not isinstance(component_id, str) or not isinstance(bundle_path, str):
            raise ControllerError("STRIDE wave references an incomplete or unknown component entry")
        attempt = claimed_attempts.get(component_id)
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise ControllerError(f"STRIDE wave has invalid attempt accounting for {component_id}")
        attempt_artifact = stride_dispatch_waves.attempt_artifact(component_id, attempt)
        _resolve_artifact_path(output_dir, attempt_artifact).parent.mkdir(parents=True, exist_ok=True)
        if component_id in seen:
            raise ControllerError(f"duplicate dispatch component id: {component_id}")
        seen.add(component_id)
        canonical_bundle = _resolve_artifact_path(output_dir, bundle_path)
        bundle = _load_json_object(canonical_bundle, contract="stride-evidence-bundle-v1")
        bundle_component = bundle.get("component")
        if not isinstance(bundle_component, dict) or bundle_component.get("id") != component_id:
            raise ControllerError(f"evidence bundle component mismatch for {component_id}")
        slices = bundle.get("source_slices")
        if not isinstance(slices, list):
            raise ControllerError(f"stride-evidence-bundle-v1 has no source_slices for {component_id}")
        bundle_receipt = _validated_json_receipt(
            output_dir,
            bundle_path,
            schema_id="schemas/stride-evidence-bundle.schema.json#v1",
            record_count=len(slices),
        )
        structured.append(bundle_receipt)
        architecture_context_path = component.get("architecture_context_path")
        architecture_context_sha256 = component.get("architecture_context_sha256")
        architecture_context_receipt: dict[str, Any] | None = None
        if architecture_context_path is not None or architecture_context_sha256 is not None:
            if not isinstance(architecture_context_path, str) or not isinstance(architecture_context_sha256, str):
                raise ControllerError(f"incomplete architecture-context projection for {component_id}")
            architecture_value = _validate_json_artifact(
                _resolve_artifact_path(output_dir, architecture_context_path),
                PLUGIN_ROOT / "schemas" / "stride-component-architecture-context.schema.json",
                contract="stride-component-architecture-context-v1",
            )
            if architecture_value.get("component_id") != component_id:
                raise ControllerError(f"architecture-context projection component mismatch for {component_id}")
            attributes = architecture_value.get("attributes")
            if not isinstance(attributes, dict) or not attributes:
                raise ControllerError(f"architecture-context projection has no attributes for {component_id}")
            architecture_context_receipt = _validated_json_receipt(
                output_dir,
                architecture_context_path,
                schema_id="schemas/stride-component-architecture-context.schema.json#v1",
                record_count=len(attributes),
            )
            if architecture_context_receipt["sha256"] != architecture_context_sha256:
                raise ControllerError(f"architecture-context manifest hash is stale for {component_id}")
            structured.append(architecture_context_receipt)
        business_context_path = component.get("business_context_path")
        business_context_sha256 = component.get("business_context_sha256")
        business_context_receipt: dict[str, Any] | None = None
        if business_context_path is not None or business_context_sha256 is not None:
            if not isinstance(business_context_path, str) or not isinstance(business_context_sha256, str):
                raise ControllerError(f"incomplete business-context projection for {component_id}")
            business_value = _validate_json_artifact(
                _resolve_artifact_path(output_dir, business_context_path),
                PLUGIN_ROOT / "schemas" / "stride-component-business-context.schema.json",
                contract="stride-component-business-context-v1",
            )
            if business_value.get("component_id") != component_id:
                raise ControllerError(f"business-context projection component mismatch for {component_id}")
            attributes = business_value.get("attributes")
            if not isinstance(attributes, dict) or not attributes:
                raise ControllerError(f"business-context projection has no attributes for {component_id}")
            business_context_receipt = _validated_json_receipt(
                output_dir,
                business_context_path,
                schema_id="schemas/stride-component-business-context.schema.json#v1",
                record_count=len(attributes),
            )
            if business_context_receipt["sha256"] != business_context_sha256:
                raise ControllerError(f"business-context manifest hash is stale for {component_id}")
            structured.append(business_context_receipt)
        security_context_projections: list[dict[str, str]] = []
        declared_security_contexts = component.get("security_context_projections", [])
        if not isinstance(declared_security_contexts, list):
            raise ControllerError(f"security-context projections must be an array for {component_id}")
        seen_security_context_ids: set[str] = set()
        for declared_projection in declared_security_contexts:
            if not isinstance(declared_projection, dict):
                raise ControllerError(f"security-context projection entry is invalid for {component_id}")
            context_id = declared_projection.get("context_id")
            artifact_path = declared_projection.get("artifact_path")
            declared_sha256 = declared_projection.get("sha256")
            if (
                not isinstance(context_id, str)
                or context_id in seen_security_context_ids
                or not isinstance(artifact_path, str)
                or not isinstance(declared_sha256, str)
            ):
                raise ControllerError(f"security-context projection metadata is invalid for {component_id}")
            seen_security_context_ids.add(context_id)
            projection_value = _validate_json_artifact(
                _resolve_artifact_path(output_dir, artifact_path),
                PLUGIN_ROOT / "schemas" / "stride-component-security-context.schema.json",
                contract="stride-component-security-context-v1",
            )
            if projection_value.get("component_id") != component_id or projection_value.get("context_id") != context_id:
                raise ControllerError(f"security-context projection content mismatch for {component_id}")
            projection_records = projection_value.get("records")
            if not isinstance(projection_records, list) or not projection_records:
                raise ControllerError(f"security-context projection is empty for {component_id}")
            projection_receipt = _validated_json_receipt(
                output_dir,
                artifact_path,
                schema_id="schemas/stride-component-security-context.schema.json#v1",
                record_count=len(projection_records),
            )
            if projection_receipt["sha256"] != declared_sha256:
                raise ControllerError(f"security-context manifest hash is stale for {component_id}")
            structured.append(projection_receipt)
            security_context_projections.append(
                {"context_id": context_id, "artifact_path": artifact_path, "sha256": projection_receipt["sha256"]}
            )
        taxonomy_path, taxonomy_sha256 = _context_v2_taxonomy_slice(output_dir, component_id)
        taxonomy_receipt = _validated_text_receipt(
            output_dir,
            taxonomy_path,
            schema_id="schemas/threat-taxonomy-slice.schema.yaml#v1",
            record_count=1,
            max_bytes=32_768,
        )
        if taxonomy_receipt["sha256"] != taxonomy_sha256:
            raise ControllerError(f"taxonomy slice hash changed before receipt for {component_id}")
        structured.append(taxonomy_receipt)
        analysis = {
            "depth": "light"
            if bool(claimed_component.get("cheap_stride", component.get("cheap_stride", False)))
            else "full",
            "max_turns": int(claimed_component.get("max_turns") or component.get("max_turns") or 1),
            "sampling_required": bool(
                claimed_component.get("sampling_required", component.get("sampling_required", False))
            ),
            "file_count": int(component.get("file_count") or 0),
            "estimated_threat_count": str(component.get("estimated_threat_count_label") or "moderate"),
            "stride_profile": cfg.get("stride_profile"),
        }
        lens_ids = list(component.get("lens_ids") or [])
        llm_policy_projection = _write_stride_component_llm_policy(
            output_dir,
            component_id=component_id,
            # Only components carrying the LLM lens can answer the policy
            # questions, so nobody else pays for the artifact.
            attributes=run_llm_policy if "llm" in lens_ids else None,
        )
        llm_policy_path = llm_policy_projection[0] if llm_policy_projection is not None else None
        llm_policy_receipt = llm_policy_projection[1] if llm_policy_projection is not None else None
        if llm_policy_receipt is not None:
            structured.append(llm_policy_receipt)
        repository_projection = _write_stride_component_repository_roots(
            output_dir,
            component_id=component_id,
            bundle=bundle,
            source_registry_path=repository_registry,
        )
        repository_projection_path = repository_projection[0] if repository_projection is not None else None
        repository_projection_receipt = repository_projection[1] if repository_projection is not None else None
        if repository_projection_receipt is not None:
            structured.append(repository_projection_receipt)
        context_plan_path, context_plan_receipt = _write_stride_component_context_plan(
            output_dir,
            component_id=component_id,
            manifest_sha256=manifest_sha256,
            analysis=analysis,
            lens_ids=lens_ids,
            bundle_path=bundle_path,
            bundle_sha256=bundle_receipt["sha256"],
            taxonomy_path=taxonomy_path,
            taxonomy_sha256=taxonomy_sha256,
            architecture_context_path=(architecture_context_path if architecture_context_receipt is not None else None),
            architecture_context_sha256=(
                architecture_context_receipt["sha256"] if architecture_context_receipt is not None else None
            ),
            business_context_path=(business_context_path if business_context_receipt is not None else None),
            business_context_sha256=(
                business_context_receipt["sha256"] if business_context_receipt is not None else None
            ),
            llm_policy_path=llm_policy_path,
            llm_policy_sha256=(llm_policy_receipt["sha256"] if llm_policy_receipt is not None else None),
            repository_projection_path=repository_projection_path,
            repository_projection_sha256=(
                repository_projection_receipt["sha256"] if repository_projection_receipt is not None else None
            ),
            security_context_projections=security_context_projections,
        )
        structured.append(context_plan_receipt)
        input_artifacts = [context_plan_path, bundle_path, taxonomy_path]
        if architecture_context_receipt is not None:
            input_artifacts.append(architecture_context_path)
        if business_context_receipt is not None:
            input_artifacts.append(business_context_path)
        if llm_policy_path is not None:
            input_artifacts.append(llm_policy_path)
        if repository_projection_path is not None:
            input_artifacts.append(repository_projection_path)
        input_artifacts.extend(row["artifact_path"] for row in security_context_projections)
        jobs.append(
            {
                "schema_version": 1,
                "job_id": f"stride:{component_id}:attempt-{attempt}",
                "component_id": component_id,
                "attempt": attempt,
                "semantic_role": "stride_analyzer",
                **_context_v2_job_metadata(cfg, "stride_analyzer"),
                "analysis_depth": analysis["depth"],
                "max_turns": analysis["max_turns"],
                "sampling_required": analysis["sampling_required"],
                "file_count": analysis["file_count"],
                "estimated_threat_count": analysis["estimated_threat_count"],
                "lens_ids": lens_ids,
                "evidence_bundle_sha256": bundle_receipt["sha256"],
                "taxonomy_slice_path": taxonomy_path,
                "taxonomy_slice_sha256": taxonomy_sha256,
                "context_plan_path": context_plan_path,
                "context_plan_sha256": context_plan_receipt["sha256"],
                "input_artifacts": input_artifacts,
                "output_artifacts": [attempt_artifact],
                "unresolved_decision_keys": [f"stride:{category}" for category in "STRIDE"],
            }
        )
        if security_context_projections:
            jobs[-1]["security_context_projections"] = security_context_projections
        if repository_projection_path is not None and repository_projection_receipt is not None:
            jobs[-1]["repository_projection_path"] = repository_projection_path
            jobs[-1]["repository_projection_sha256"] = repository_projection_receipt["sha256"]
        if architecture_context_receipt is not None:
            jobs[-1]["architecture_context_path"] = architecture_context_path
            jobs[-1]["architecture_context_sha256"] = architecture_context_receipt["sha256"]
        if business_context_receipt is not None:
            jobs[-1]["business_context_path"] = business_context_path
            jobs[-1]["business_context_sha256"] = business_context_receipt["sha256"]
        if llm_policy_receipt is not None:
            jobs[-1]["llm_policy_path"] = llm_policy_path
            jobs[-1]["llm_policy_sha256"] = llm_policy_receipt["sha256"]
    action = {
        **_context_v2_common(output_dir, cfg),
        "action": "dispatch_parallel",
        "next_boundary": _checked_next_boundary("context-v2-post-stride"),
        "dispatch_jobs": jobs,
        "artifact_receipts": structured,
        "receipts": [
            f"Context-v2 STRIDE wave admitted for {len(jobs)} component(s) after persisted attempt accounting"
        ],
    }
    try:
        already_issued = context_routing.action_already_issued(action, output_dir)
    except context_routing.ContextRoutingError as exc:
        raise ControllerError(f"context-v2 dispatch replay rejected: {exc}") from exc
    if not already_issued:
        _prepare_context_v2_dispatch_outputs(output_dir, jobs)
    return _validate_action(action)


def context_v2_prepare_stride(output_dir: Path) -> dict[str, Any]:
    """Build context-v2 bundles and return the first persisted STRIDE wave."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    controls_path = output_dir / ".security-controls.json"
    analyst_context_path = output_dir / ".stride-analyst-context.json"
    repo_root = Path(str(cfg.get("repo_root") or output_dir))
    _run_script("validate_fragment.py", ["security-controls", str(controls_path)])
    _normalize_context_v2_analyst_context(output_dir)
    _validate_context_v2_analyst_context(output_dir, repo_root=repo_root)
    build_args = [
        str(output_dir),
        "--depth",
        str(cfg.get("assessment_depth") or "standard"),
        "--ceiling",
        str(cfg.get("max_stride_components") or 12),
        "--analyst-context",
        str(analyst_context_path),
        "--context-v2",
        "--repo-root",
        str(cfg.get("repo_root") or output_dir),
    ]
    repository_registry = output_dir / ".stride-repository-registry.json"
    try:
        from build_stride_evidence_bundles import BundleError, write_repository_registry

        write_repository_registry(repo_root, repository_registry)
    except (BundleError, OSError) as exc:
        raise ControllerError(f"cannot build context-v2 repository registry: {exc}") from exc
    build_args.extend(["--repository-registry", str(repository_registry)])
    _run_script("build_stride_dispatch_manifest.py", build_args)
    manifest_path = output_dir / ".stride-dispatch-manifest.json"
    _run_script("validate_dispatch_manifest.py", [str(manifest_path), str(output_dir)])
    manifest = _load_json_object(manifest_path, contract="stride-dispatch-manifest-v2")
    action = _context_v2_stride_wave_action(output_dir, cfg, manifest, initialize=True)
    if action is None:
        raise ControllerError("new context-v2 STRIDE wave plan unexpectedly has no pending components")
    return action


def _projection_size_is_current(path: Path, value: dict[str, Any]) -> None:
    limits = value.get("limits")
    try:
        actual = path.stat().st_size
    except OSError as exc:
        raise ControllerError(f"cannot stat context projection {path}: {exc}") from exc
    if not isinstance(limits, dict) or limits.get("serialized_bytes") != actual:
        raise ControllerError(f"context projection size metadata is stale for {path.name}")


def _projection_semantics_are_current(
    value: dict[str, Any],
    expected: dict[str, Any],
    *,
    contract: str,
) -> None:
    """Compare every deterministic field except the self-referential byte count."""
    actual_semantics = json.loads(json.dumps(value))
    expected_semantics = json.loads(json.dumps(expected))
    for document in (actual_semantics, expected_semantics):
        limits = document.get("limits")
        if isinstance(limits, dict):
            limits.pop("serialized_bytes", None)
    if actual_semantics != expected_semantics:
        raise ControllerError(f"{contract} differs from its deterministic projection")


def _context_v2_evidence_projection_receipt(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct and receipt the exact selected evidence sample."""
    from build_post_stride_contexts import (  # noqa: PLC0415
        PostStrideContextError,
        build_evidence_context,
        validate_evidence_context_sources,
    )

    relative = ".dispatch-context/post-stride/evidence-sample.json"
    path = output_dir / relative
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas/evidence-verifier-context.schema.json",
        contract="evidence-verifier-context-v1",
    )
    try:
        merged_payload = (output_dir / ".threats-merged.json").read_bytes()
        expected = build_evidence_context(
            merged_payload,
            Path(str(cfg.get("repo_root") or output_dir)),
            depth=str(cfg.get("assessment_depth") or "standard"),
            noncritical_cap=int(cfg.get("evidence_verifier_max_findings") or 0),
        )
        validate_evidence_context_sources(
            value,
            merged_payload,
            Path(str(cfg.get("repo_root") or output_dir)),
        )
    except (OSError, PostStrideContextError) as exc:
        raise ControllerError(f"evidence-verifier-context-v1 validation failed: {exc}") from exc
    _projection_semantics_are_current(value, expected, contract="evidence-verifier-context-v1")
    _projection_size_is_current(path, value)
    return _validated_json_receipt(
        output_dir,
        relative,
        schema_id="schemas/evidence-verifier-context.schema.json#v1",
        record_count=len(value["samples"]),
    )


def _context_v2_synthesis_projection_receipt(output_dir: Path, *, generated: bool) -> dict[str, Any]:
    """Reconstruct and receipt one exact post-STRIDE synthesis projection."""
    from build_post_stride_contexts import (  # noqa: PLC0415
        PostStrideContextError,
        build_synthesis_contexts,
    )

    if generated:
        relative = ".dispatch-context/post-stride/generated-threats.json"
        schema_name = "post-stride-generated-threats.schema.json"
        record_key = "threats"
        expected_index = 0
    else:
        relative = ".dispatch-context/post-stride/proposed-mitigations.json"
        schema_name = "post-stride-proposed-mitigations.schema.json"
        record_key = "mitigations"
        expected_index = 1
    path = output_dir / relative
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas" / schema_name,
        contract=f"{schema_name}#v1",
    )
    try:
        expected = build_synthesis_contexts(
            (output_dir / ".threats-merged.json").read_bytes(),
            (output_dir / ".components.json").read_bytes(),
        )[expected_index]
    except (OSError, PostStrideContextError) as exc:
        raise ControllerError(f"{schema_name} validation failed: {exc}") from exc
    _projection_semantics_are_current(value, expected, contract=schema_name)
    _projection_size_is_current(path, value)
    return _validated_json_receipt(
        output_dir,
        relative,
        schema_id=f"schemas/{schema_name}#v1",
        record_count=len(value[record_key]),
    )


def _context_v2_after_merge(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Advance from a finalized merge to evidence verification or triage."""
    _run_script(
        "validate_intermediate.py",
        ["threats_merged", str(output_dir / ".threats-merged.json")],
    )
    merged = _load_json_object(output_dir / ".threats-merged.json", contract="threats-merged-v1")
    threats = merged.get("threats")
    if not isinstance(threats, list):
        raise ControllerError("threats-merged-v1 artifact has no threats array")
    human: list[str] = []
    _context_v2_run_posture_emitters(output_dir, cfg, human)
    if threats and int(cfg.get("evidence_verifier_max_findings") or 0) != 0:
        _run_script(
            "build_post_stride_contexts.py",
            [
                "evidence",
                "--output-dir",
                str(output_dir),
                "--repo-root",
                str(cfg.get("repo_root") or output_dir),
                "--depth",
                str(cfg.get("assessment_depth") or "standard"),
                "--noncritical-cap",
                str(int(cfg.get("evidence_verifier_max_findings") or 0)),
            ],
        )
        evidence_context = _validate_json_artifact(
            output_dir / ".dispatch-context/post-stride/evidence-sample.json",
            PLUGIN_ROOT / "schemas/evidence-verifier-context.schema.json",
            contract="evidence-verifier-context-v1",
        )
        if not evidence_context["samples"]:
            return _context_v2_after_evidence(output_dir, cfg)
        structured = [_context_v2_evidence_projection_receipt(output_dir, cfg)]
        return _context_v2_dispatch(
            output_dir,
            cfg,
            role="evidence_verifier",
            job_id="phase10a-evidence",
            next_boundary="context-v2-post-evidence",
            input_artifacts=[".dispatch-context/post-stride/evidence-sample.json"],
            output_artifacts=[".evidence-verification.json"],
            decision_keys=["sampled_evidence_verdicts"],
            receipts=structured,
        )
    return _context_v2_after_evidence(output_dir, cfg)


def _context_v2_after_evidence(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Run deterministic triage and stop only for qualitative synthesis."""
    receipts: list[str] = []
    _run_script(
        "validate_intermediate.py",
        ["threats_merged", str(output_dir / ".threats-merged.json")],
    )
    if (output_dir / ".evidence-verification.json").is_file():
        evidence_summary_valid = True
        try:
            verification = _validate_evidence_verification(output_dir / ".evidence-verification.json")
            context = _validate_json_artifact(
                output_dir / ".dispatch-context/post-stride/evidence-sample.json",
                PLUGIN_ROOT / "schemas/evidence-verifier-context.schema.json",
                contract="evidence-verifier-context-v1",
            )
            from _atomic_io import atomic_write_json  # noqa: PLC0415
            from build_post_stride_contexts import (  # noqa: PLC0415
                apply_evidence_verification,
                evidence_verification_is_applied,
                validate_evidence_context_sources,
            )

            merged_path = output_dir / ".threats-merged.json"
            merged_payload = merged_path.read_bytes()
            merged = _load_json_object(merged_path, contract="threats-merged-v1")
            if evidence_verification_is_applied(merged, verification):
                # A re-entered boundary reads the artifact that reclassify_components.py
                # rewrote below, so the payload hash no longer matches the selected
                # sample. The verdicts are already annotated; skip without reporting
                # staleness, which would degrade the guard for healthy evidence.
                receipts.append("evidence verification already applied")
            else:
                validate_evidence_context_sources(
                    context,
                    merged_payload,
                    Path(str(cfg.get("repo_root") or output_dir)),
                )
                annotated = apply_evidence_verification(merged, context, verification)
                staged_path = output_dir / ".dispatch-context/post-stride/threats-merged-verified.json"
                try:
                    atomic_write_json(staged_path, annotated, sort_keys=False)
                    _run_script("validate_intermediate.py", ["threats_merged", str(staged_path)])
                    _validate_evidence_verification(output_dir / ".evidence-verification.json", staged_path)
                    staged_path.replace(merged_path)
                finally:
                    staged_path.unlink(missing_ok=True)
        except ControllerError as exc:
            # Evidence verification is optional enrichment. Invalid side-channel
            # data supplies no refutation signal, while the guard still inspects
            # annotations in the canonical merged-threat artifact.
            evidence_summary_valid = False
            receipts.append("evidence verification rejected: invalid contract")
            _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")
        except (OSError, ValueError) as exc:
            evidence_summary_valid = False
            receipts.append("evidence verification rejected: stale or invalid projection")
            _append_event(output_dir, "ORCHESTRATION_GATE_WARN", str(exc), level="WARN")
        _best_effort_script(
            output_dir,
            "guard_evidence_verification.py",
            [str(output_dir), *([] if evidence_summary_valid else ["--ignore-summary"])],
            receipts,
        )
    # Deterministic source scanners use provisional component ids because the
    # merge stage does not own the run's component registry. Resolve those ids
    # before ranking or synthesis consumes the canonical merged register. The
    # legacy path gets the same repair later from auto_emitter_pass.sh, but
    # context-v2 has no YAML artifact at this boundary.
    _run_script(
        "reclassify_components.py",
        ["--merged-only", "--strict", str(output_dir)],
    )
    _run_script(
        "validate_intermediate.py",
        ["threats_merged", str(output_dir / ".threats-merged.json")],
    )
    _run_script(
        "triage_validate_ratings.py",
        [str(output_dir), "--depth", str(cfg.get("assessment_depth") or "standard")],
    )
    try:
        _run_script(
            "triage_compute_ranking.py",
            [
                str(output_dir),
                "--repo-root",
                str(cfg.get("repo_root") or output_dir),
                "--force",
                "--bootstrap-yaml",
            ],
        )
    except ControllerError:
        merged = _load_json_object(output_dir / ".threats-merged.json", contract="threats-merged-v1")
        threats = merged.get("threats")
        if not isinstance(threats, list):
            raise ControllerError("threats-merged-v1 artifact has no threats array")
        inputs = [".threats-merged.json"]
        if (output_dir / ".triage-flags.json").is_file():
            inputs.append(".triage-flags.json")
        if (output_dir / ".dispatch-context/architecture/recon-summary-context.json").is_file():
            inputs.append(".dispatch-context/architecture/recon-summary-context.json")
        receipt = _validated_json_receipt(
            output_dir,
            ".threats-merged.json",
            schema_id="schemas/threats-merged.schema.yaml#v1",
            record_count=len(threats),
        )
        repair_receipts = [receipt]
        if ".dispatch-context/architecture/recon-summary-context.json" in inputs:
            repair_receipts.append(_context_v2_recon_projection_receipt(output_dir))
        return _context_v2_dispatch(
            output_dir,
            cfg,
            role="triage_validator",
            job_id="phase10b-triage-repair",
            next_boundary="context-v2-post-triage",
            input_artifacts=inputs,
            output_artifacts=[".triage-flags.json", ".threats-merged.json"],
            decision_keys=["triage_ranking"],
            receipts=repair_receipts,
        )
    return _context_v2_after_triage(output_dir, cfg)


def _context_v2_after_triage(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Validate triage output and select optional qualitative synthesis."""
    _run_script(
        "validate_intermediate.py",
        ["threats_merged", str(output_dir / ".threats-merged.json")],
    )
    _run_script(
        "validate_intermediate.py",
        ["triage_flags", str(output_dir / ".triage-flags.json")],
    )
    flags = _load_json_object(output_dir / ".triage-flags.json", contract="triage-flags-v2")
    flag_values = flags.get("flags")
    if not isinstance(flag_values, list):
        raise ControllerError("triage-flags-v2 artifact has no flags array")
    merged = _load_json_object(output_dir / ".threats-merged.json", contract="threats-merged-v1")
    threats = merged.get("threats")
    if not isinstance(threats, list):
        raise ControllerError("threats-merged-v1 artifact has no threats array")
    if threats:
        _run_script("build_post_stride_contexts.py", ["synthesis", "--output-dir", str(output_dir)])
        structured = [
            _context_v2_synthesis_projection_receipt(output_dir, generated=True),
            _context_v2_synthesis_projection_receipt(output_dir, generated=False),
        ]
        return _context_v2_dispatch(
            output_dir,
            cfg,
            role="post_stride_synthesizer",
            job_id="phase10b-root-causes",
            next_boundary="context-v2-finalize",
            input_artifacts=[
                ".dispatch-context/post-stride/generated-threats.json",
                ".dispatch-context/post-stride/proposed-mitigations.json",
            ],
            output_artifacts=[".tier-root-causes.json"],
            decision_keys=["tier_root_causes"],
            receipts=structured,
        )
    return _context_v2_finalize(output_dir, cfg)


def _context_v2_finalize(output_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Build and gate the Stage-2 handoff after the last semantic boundary."""
    from _atomic_io import atomic_write_text

    receipts: list[str] = []
    for kind, name in (
        ("mitigation-overrides", ".mitigation-overrides.json"),
        ("tier-root-causes", ".tier-root-causes.json"),
    ):
        if (output_dir / name).is_file():
            _run_script("validate_fragment.py", [kind, str(output_dir / name)])
            value = _load_json_object(output_dir / name, contract=f"{kind}-v1")
            record_value = (
                value.get("splits", []) if kind == "mitigation-overrides" else value.get("tier_root_causes", {})
            )
            record_count = len(record_value) if isinstance(record_value, (list, dict)) else 0
            receipt = _validated_json_receipt(
                output_dir,
                name,
                schema_id=f"schemas/fragments/{kind}.schema.json#v1",
                record_count=record_count,
            )
            consume_artifact_receipt(output_dir, receipt)
    _run_script(
        "build_threat_model_yaml.py",
        [
            str(output_dir),
            "--repo-root",
            str(cfg.get("repo_root") or output_dir),
            "--plugin-root",
            str(PLUGIN_ROOT),
        ],
    )
    _run_script(
        "validate_intermediate.py",
        ["threat_model_output", str(output_dir / "threat-model.yaml")],
    )
    # Context-v2 builds canonical YAML directly instead of passing through the
    # legacy post_stage1 gate. It still needs the same deterministic enrichment
    # before the P1/P2 actionability gate: scanner remediation backfill and
    # mitigation-detail hydration copy concrete steps and verification from
    # finding producers onto mitigation cards.
    _run_auto_emitter_pass(output_dir, cfg, receipts)
    _run_script("validate_mitigation_quality.py", [str(output_dir)])
    _run_script(
        "assert_completeness.py",
        [str(output_dir), "--phase", "build", "--plugin-root", str(PLUGIN_ROOT)],
    )
    atomic_write_text(
        output_dir / ".appsec-checkpoint",
        "phase=10b status=completed need_render=true runtime_generation=context-v2\n",
    )
    _append_event(output_dir, "CONTEXT_V2_STAGE1_COMPLETE", "deterministic Stage-2 handoff passed")
    return _validate_action(
        {
            **_context_v2_common(output_dir, cfg),
            "action": "run_gate",
            "receipts": ["Context-v2 Stage-1 artifacts and Stage-2 handoff gates passed", *receipts],
        }
    )


def context_v2_post_stride(output_dir: Path) -> dict[str, Any]:
    """Claim retries/next waves, then progress complete STRIDE to merge."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    manifest_path = output_dir / ".stride-dispatch-manifest.json"
    _run_script("validate_dispatch_manifest.py", [str(manifest_path), str(output_dir)])
    manifest = _load_json_object(manifest_path, contract="stride-dispatch-manifest-v2")
    next_wave = _context_v2_stride_wave_action(output_dir, cfg, manifest, initialize=False)
    if next_wave is not None:
        return next_wave
    _run_script("stride_dispatch_waves.py", ["verify", str(output_dir)])
    _run_script("merge_threats.py", ["collect", "--output-dir", str(output_dir)])
    candidates = _load_json_object(output_dir / ".merge-candidates.json", contract="merge-candidates-v1")
    groups = candidates.get("candidate_groups")
    if candidates.get("version") != 1 or not isinstance(groups, list):
        raise ControllerError("merge-candidates-v1 artifact has an invalid version or candidate_groups")
    group_ids: list[str] = []
    for group in groups:
        group_id = group.get("group_id") if isinstance(group, dict) else None
        if not isinstance(group_id, str) or not group_id:
            raise ControllerError("merge-candidates-v1 contains a candidate without group_id")
        group_ids.append(group_id)
    if len(group_ids) != len(set(group_ids)):
        raise ControllerError("merge-candidates-v1 contains duplicate group_id values")
    if len(group_ids) > 64:
        raise ControllerError("merge-candidates-v1 exceeds the 64-group semantic admission cap")
    if group_ids:
        source_receipt = _validated_json_receipt(
            output_dir,
            ".merge-candidates.json",
            schema_id="schemas/merge-candidates.schema.json#v1",
            record_count=len(group_ids),
        )
        source_payload = consume_artifact_receipt(output_dir, source_receipt)
        candidates = json.loads(source_payload)
        review = _write_merge_review_context(output_dir, candidates, source_payload)
        receipt = _validated_json_receipt(
            output_dir,
            ".merge-context/candidates.json",
            schema_id="schemas/merge-review-context.schema.json#v1",
            record_count=review["candidate_group_count"],
        )
        return _context_v2_dispatch(
            output_dir,
            cfg,
            role="threat_merger",
            job_id="phase9-merge-review",
            next_boundary="context-v2-post-merge",
            input_artifacts=[".merge-context/candidates.json"],
            output_artifacts=[".merge-decisions.json"],
            decision_keys=group_ids,
            receipts=[receipt],
        )
    _run_script("merge_threats.py", ["finalize", "--output-dir", str(output_dir)])
    return _context_v2_after_merge(output_dir, cfg)


def context_v2_post_merge(output_dir: Path) -> dict[str, Any]:
    """Consume merger decisions and continue until the next semantic boundary."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    if not (output_dir / ".merge-decisions.json").is_file():
        raise ControllerError("context-v2 merger dispatch did not produce .merge-decisions.json")
    decisions = _validate_json_artifact(
        output_dir / ".merge-decisions.json",
        PLUGIN_ROOT / "schemas" / "merge-decisions.schema.json",
        contract="merge-decisions-v2",
    )
    review = _validate_json_artifact(
        output_dir / ".merge-context" / "candidates.json",
        PLUGIN_ROOT / "schemas" / "merge-review-context.schema.json",
        contract="merge-review-context-v1",
    )
    try:
        candidate_payload = (output_dir / ".merge-candidates.json").read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot read merge-candidates-v1 artifact: {exc}") from exc
    if hashlib.sha256(candidate_payload).hexdigest() != review.get("source_sha256"):
        raise ControllerError("merge-candidates-v1 changed after semantic review admission")
    candidates = _load_json_object(output_dir / ".merge-candidates.json", contract="merge-candidates-v1")
    if review.get("candidate_groups") != candidates.get("candidate_groups"):
        raise ControllerError("merge review context changed after semantic review admission")
    if review.get("candidate_group_count") != len(review["candidate_groups"]):
        raise ControllerError("merge-review-context-v1 candidate group count is stale")
    review_path = output_dir / ".merge-context" / "candidates.json"
    try:
        review_bytes = review_path.read_bytes()
    except OSError as exc:
        raise ControllerError(f"cannot read merge-review-context-v1 artifact: {exc}") from exc
    limits = review.get("limits") if isinstance(review.get("limits"), dict) else {}
    if (
        limits.get("serialized_bytes") != len(review_bytes)
        or limits.get("estimated_tokens") != (len(review_bytes) + 3) // 4
    ):
        raise ControllerError("merge-review-context-v1 size metadata is stale")
    decision_ids = [str(decision.get("group_id")) for decision in decisions.get("decisions", [])]
    decision_errors = merge_decision_contract.validate_agent_decision_document(decisions, review)
    if decision_errors:
        raise ControllerError(decision_errors[0])
    decision_receipt = _validated_json_receipt(
        output_dir,
        ".merge-decisions.json",
        schema_id="schemas/merge-decisions.schema.json#v2",
        record_count=len(decision_ids),
    )
    consume_artifact_receipt(output_dir, decision_receipt)
    _run_script("merge_threats.py", ["finalize", "--output-dir", str(output_dir)])
    return _context_v2_after_merge(output_dir, cfg)


def _validate_context_v2_merge_decision_subsets(decisions: dict[str, Any], candidates: dict[str, Any]) -> None:
    """Compatibility wrapper around the shared merger producer contract."""
    errors = merge_decision_contract.validate_agent_decision_document(decisions, candidates)
    if errors:
        raise ControllerError(errors[0])


def context_v2_post_evidence(output_dir: Path) -> dict[str, Any]:
    """Continue after the optional evidence-verifier boundary."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    return _context_v2_after_evidence(output_dir, cfg)


def context_v2_post_triage(output_dir: Path) -> dict[str, Any]:
    """Continue after the exceptional focused triage boundary."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    return _context_v2_after_triage(output_dir, cfg)


def context_v2_finalize(output_dir: Path) -> dict[str, Any]:
    """Continue after optional post-STRIDE semantic synthesis."""
    output_dir, cfg = _load_context_v2_config(output_dir)
    return _context_v2_finalize(output_dir, cfg)


def _selected_coverage_errors(output_dir: Path) -> list[dict[str, str]]:
    """Blocked bounded-wave components, or [] when the gate does not apply.

    Delegates to check_stride_dispatch.selected_coverage_errors so the early
    diagnosis in post_stage1 and the hard gate below it can never disagree.
    Import failures are non-fatal: the hard gate still runs as a subprocess.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import check_stride_dispatch  # noqa: PLC0415

        return check_stride_dispatch.selected_coverage_errors(output_dir)
    except Exception:
        return []


def post_stage1(output_dir: Path) -> dict[str, Any]:
    """Run the deterministic thin-path gates after the Stage-1 agents return."""
    output_dir, cfg = _load_run_config(output_dir)
    _reject_context_v2(cfg, "post-stage1")
    config_path = output_dir / ".skill-config.json"

    # Bounded-wave coverage is checked FIRST, before the artifact precondition.
    #
    # SKILL-thin-stage1.md tells the orchestrator to stop before Analyst-B when
    # the wave plan reports `blocked`. Analyst-B is what produces
    # .threats-merged.json / .triage-flags.json / threat-model.yaml, so an
    # orchestrator that obeys that instruction used to land on the artifact
    # precondition below and be told "Stage 1 did not produce required
    # artifacts" -- which reads as its own failure and pushes it into the
    # cut-off recovery path. Running that recovery produces the artifacts, and
    # then check_stride_dispatch.py (further down) hard-fails with exit 4
    # anyway. Both branches aborted, and the second one only after paying for a
    # full merge+triage pass (2026-07-20 juice-shop: ~20 min / $5.75 spent
    # after the run was already doomed).
    #
    # Reporting the real cause here keeps the two gates consistent: an
    # orchestrator that correctly stopped gets the correct diagnosis instead of
    # being blamed for the artifacts it was forbidden to create.
    coverage_errors = _selected_coverage_errors(output_dir)
    if coverage_errors:
        detail = "; ".join(f"{e['component_id']}: {e['reason']}" for e in coverage_errors)
        raise ControllerError(
            "Selected STRIDE coverage is incomplete after the bounded retry budget "
            f"({detail}). Merge and triage were correctly skipped -- the report must "
            "not claim coverage for these components. Attempt counts persist across "
            "resume, so a plain --resume hits the same block. Recover by fixing what "
            "made the component fail (a turn budget too small for its file footprint "
            "is the common cause) and then granting one more attempt with "
            "APPSEC_STRIDE_MAX_ATTEMPTS=3; a fresh --full run also resets the counts "
            "but discards the merge and triage already produced."
        )

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
    _run_auto_emitter_pass(output_dir, cfg, receipts)

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


def post_stage1a(output_dir: Path) -> dict[str, Any]:
    """Finalize architecture artifacts and open the Stage-1b dispatch gate."""
    output_dir, cfg = _load_run_config(output_dir)
    _reject_context_v2(cfg, "post-stage1a")
    config_path = output_dir / ".skill-config.json"
    _gate_architecture_stage(output_dir, cfg)
    return {
        "schema_version": 1,
        "action": "dispatch_agent",
        "mode": cfg["mode"],
        "stage": "stage1b",
        "instruction_file": str(THIN_STAGE1B_RUNTIME),
        "config_path": str(config_path),
        "dispatch_values": _dispatch_values(cfg),
        "receipts": ["Stage-1a component, topology, and assessment-input gates passed"],
    }


def _bind_finalized_component_fingerprint(output_dir: Path) -> None:
    """Bind derived data-flow metadata to the finalized component inventory."""
    try:
        flows = json.loads((output_dir / ".data-flows.json").read_text(encoding="utf-8"))
        receipt = json.loads((output_dir / ".component-inventory-finalization.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControllerError(f"cannot bind finalized component fingerprint: {exc}") from exc
    if not isinstance(flows, dict) or not isinstance(receipt, dict):
        raise ControllerError("cannot bind finalized component fingerprint: artifacts must be JSON objects")
    fingerprint = receipt.get("component_inventory_fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint):
        raise ControllerError("cannot bind finalized component fingerprint: receipt fingerprint is invalid")
    flows["component_inventory_fingerprint"] = fingerprint
    from _atomic_io import atomic_write_json

    atomic_write_json(output_dir / ".data-flows.json", flows, sort_keys=False)


def _gate_architecture_stage(
    output_dir: Path,
    cfg: dict[str, Any],
    *,
    controller_owned_handoff: bool = False,
) -> None:
    """Validate the Phase 3-6 artifacts and build the boundary assessment input.

    Shared by the legacy Stage-1a gate and the context-v2 architecture
    boundary so both generations enforce one architecture contract.
    """
    required = [
        ".recon-summary.md",
        ".components.json",
        ".data-flows.json",
        ".assets.json",
        ".attack-surface-overrides.json",
    ]
    if not controller_owned_handoff:
        required.append(".component-inventory-finalization.json")
    missing = [name for name in required if not (output_dir / name).is_file()]
    if missing:
        raise ControllerError(f"Stage 1a did not produce required artifacts: {', '.join(missing)}")
    repo_root = Path(str(cfg.get("repo_root") or output_dir))
    for fragment_type, name in (
        ("data-flows", ".data-flows.json"),
        ("assets", ".assets.json"),
        ("attack-surface-overrides", ".attack-surface-overrides.json"),
    ):
        validate_args = [fragment_type, str(output_dir / name)]
        if fragment_type == "data-flows":
            validate_args.extend(["--repo-root", str(repo_root)])
        _run_script("validate_fragment.py", validate_args)
    if controller_owned_handoff:
        _run_script(
            "finalize_component_inventory.py",
            ["--repo-root", str(repo_root), "--output-dir", str(output_dir)],
        )
        _bind_finalized_component_fingerprint(output_dir)
    _run_script(
        "finalize_component_inventory.py",
        ["--repo-root", str(repo_root), "--output-dir", str(output_dir), "--validate-only"],
    )
    _run_script(
        "build_trust_boundary_assessment_input.py",
        [
            "--repo-root",
            str(repo_root),
            "--output-dir",
            str(output_dir),
            "--depth",
            str(cfg.get("assessment_depth") or "standard"),
        ],
    )
    if budget_watchdog.has_active_critical_claim(output_dir):
        from _atomic_io import atomic_write_text

        atomic_write_text(
            output_dir / ".appsec-checkpoint",
            "phase=7 status=aborted reason=budget-critical-before-boundary\n",
        )
        raise ControllerError(_boundary_budget_abort_reason(cfg))
    if controller_owned_handoff:
        from _atomic_io import atomic_write_text

        atomic_write_text(
            output_dir / ".appsec-checkpoint",
            "phase=6 status=completed need_boundary_assessment=true\n",
        )
    checkpoint = {}
    try:
        checkpoint = dict(
            part.split("=", 1)
            for part in (output_dir / ".appsec-checkpoint").read_text(encoding="utf-8").split()
            if "=" in part
        )
    except OSError:
        pass
    if not (
        checkpoint.get("phase") == "6"
        and checkpoint.get("status") == "completed"
        and checkpoint.get("need_boundary_assessment") == "true"
    ):
        raise ControllerError(
            "Stage 1a completion checkpoint is missing or invalid; expected "
            "phase=6 status=completed need_boundary_assessment=true"
        )
    _append_event(output_dir, "POST_STAGE1A_GATES_PASSED", "architecture handoff and boundary input verified")


def finalize_stage1b(output_dir: Path) -> dict[str, Any]:
    """Promote candidate output and require complete deterministic coverage."""
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"
    _gate_trust_boundary_promotion(output_dir, cfg)
    return {
        "schema_version": 1,
        "action": "run_gate",
        "mode": cfg["mode"],
        "stage": "stage1b",
        "config_path": str(config_path),
        "receipts": ["Stage-1b candidates promoted; mandatory signal coverage passed"],
    }


def _gate_trust_boundary_promotion(output_dir: Path, cfg: dict[str, Any]) -> None:
    """Promote Phase-7 candidates and require complete deterministic coverage.

    Shared by the legacy Stage-1b gate and the context-v2 boundary transition.
    """
    from _atomic_io import atomic_write_text

    candidates = output_dir / ".trust-boundary-candidates.json"
    assessment = output_dir / ".trust-boundary-assessment-input.json"
    if not candidates.is_file():
        raise ControllerError("Stage 1b agent did not produce .trust-boundary-candidates.json")
    args = [
        "promote",
        "--repo-root",
        str(cfg.get("repo_root") or output_dir),
        "--output-dir",
        str(output_dir),
        "--candidates",
        str(candidates),
        "--assessment-input",
        str(assessment),
    ]
    prior_model = output_dir / "threat-model.yaml"
    if prior_model.is_file():
        args.extend(["--prior-model", str(prior_model)])
    _run_script("prepare_trust_boundary_context.py", args)
    for name in (".trust-boundaries.json", ".trust-boundary-diagnostics.json", ".trust-boundary-coverage.json"):
        if not (output_dir / name).is_file():
            raise ControllerError(f"Stage 1b gate did not produce required artifact {name}")
    atomic_write_text(
        output_dir / ".appsec-checkpoint",
        "phase=7 status=completed need_threat_analysis=true\n",
    )
    _append_event(output_dir, "POST_STAGE1B_GATES_PASSED", "candidate promotion and signal coverage verified")


def post_stage1c(output_dir: Path) -> dict[str, Any]:
    """Compatibility wrapper for the renamed threat-analysis/triage stage."""
    action = post_stage1(output_dir)
    action["stage"] = "stage1c"
    return action


_ABUSE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def _finalized_abuse_verdicts(output_dir: Path, candidates: list[str]) -> list[str]:
    """Candidate ids whose verdict file on disk is already fully decided.

    A verifier writes `.abuse-case-verdict-<AC-ID>.json` at a fixed path and
    pre-seeds it before investigating, so dispatching a second verifier for an
    id that is already verified DESTROYS the finished result — and when the
    second run is cut off mid-chain the merge records the chain as
    `inconclusive` with an empty excerpt (juice-shop 2026-07-31: AC-T-002 was
    confirmed end-to-end, then clobbered). Two dispatchers can reach the same
    run (the skill's Stage-1d runtime and the analyst's Phase 10c), and a
    `--resume` re-enters this gate as well, so the fan-out is filtered here
    rather than trusting either caller to dispatch only once. Partly-finalized
    and untouched pre-seed files are NOT skipped — those still need a verifier.
    """
    try:
        sys.path.insert(0, str(SCRIPT_DIR))
        import verify_abuse_cases  # noqa: PLC0415
    except Exception:
        return []
    done: list[str] = []
    for candidate in candidates:
        path = output_dir / f".abuse-case-verdict-{candidate}.json"
        try:
            verdict = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(verdict, dict) and verify_abuse_cases.is_finalized_verdict(verdict):
            done.append(candidate)
    return done


def _context_v2_abuse_candidate_receipt(
    output_dir: Path,
    candidate_id: str,
    repo_root: Path,
) -> dict[str, Any]:
    """Reconstruct one candidate projection and bind it to the complete match set."""
    from build_abuse_case_contexts import AbuseContextError, project_candidate  # noqa: PLC0415

    relative = f".dispatch-context/abuse-cases/{candidate_id}.json"
    path = output_dir / relative
    value = _validate_json_artifact(
        path,
        PLUGIN_ROOT / "schemas/abuse-case-verifier-context.schema.json",
        contract="abuse-case-verifier-context-v1",
    )
    try:
        expected = project_candidate(
            (output_dir / ".abuse-case-matches.json").read_bytes(),
            candidate_id,
            repo_root=repo_root,
        )
    except (OSError, AbuseContextError) as exc:
        raise ControllerError(f"abuse-case-verifier-context-v1 validation failed: {exc}") from exc
    _projection_semantics_are_current(value, expected, contract="abuse-case-verifier-context-v1")
    _projection_size_is_current(path, value)
    return _validated_json_receipt(
        output_dir,
        relative,
        schema_id="schemas/abuse-case-verifier-context.schema.json#v1",
        record_count=len(value["candidate"]),
    )


def prepare_abuse(output_dir: Path) -> dict[str, Any]:
    """Match abuse cases and return a bounded verifier fan-out action."""
    output_dir, cfg = _load_run_config(output_dir)
    config_path = output_dir / ".skill-config.json"
    common = {
        "schema_version": 1,
        "mode": cfg["mode"],
        "stage": "stage1d",
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
    # A failed matcher normally degrades to a receipt — the library case set is
    # best-effort. Cases this run was explicitly given are not: an unreadable
    # file or an unknown id aborts the matcher before it writes any match, so
    # degrading here would silently drop exactly what the operator asked for.
    if match.returncode != 0 and (cfg.get("abuse_case_files") or cfg.get("only_abuse_case_ids")):
        detail = (match.stderr or match.stdout or "").strip()
        raise ControllerError(
            f"match_abuse_cases.py rejected the per-scan abuse-case selection (exit {match.returncode}): {detail}"
        )
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
    if already := _finalized_abuse_verdicts(output_dir, candidates):
        receipts.append("already verified, not re-dispatched: " + ", ".join(already))
        candidates = [item for item in candidates if item not in already]
    if not candidates or budget_watchdog.has_active_critical_claim(output_dir):
        return {**common, "action": "run_gate", "candidates": candidates, "receipts": receipts}
    if (cfg.get("runtime_generation") or LEGACY_GENERATION) == CONTEXT_V2_GENERATION:
        projection_args = ["--output-dir", str(output_dir), "--repo-root", repo_root]
        for candidate in candidates:
            projection_args.extend(["--candidate", candidate])
        _run_script("build_abuse_case_contexts.py", projection_args)
        artifact_receipts = [
            _context_v2_abuse_candidate_receipt(output_dir, candidate, Path(repo_root)) for candidate in candidates
        ]
        jobs = [
            {
                "schema_version": 1,
                "job_id": f"phase10c-abuse-{candidate}",
                "semantic_role": "abuse_case_verifier",
                "candidate_id": candidate,
                **_context_v2_job_metadata(cfg, "abuse_case_verifier"),
                "input_artifacts": [f".dispatch-context/abuse-cases/{candidate}.json"],
                "output_artifacts": [f".abuse-case-verdict-{candidate}.json"],
                "unresolved_decision_keys": [candidate],
            }
            for candidate in candidates
        ]
        action = {
            **common,
            "action": "dispatch_parallel",
            "instruction_file": str(THIN_STAGE1D_RUNTIME),
            "semantic_role": "abuse_case_verifier",
            "dispatch_jobs": jobs,
            "artifact_receipts": artifact_receipts,
            "unresolved_decision_keys": candidates,
            "candidates": candidates,
            "candidate_titles": _abuse_candidate_titles(output_dir, candidates),
            "receipts": receipts,
        }
        _prepare_context_v2_dispatch_outputs(output_dir, jobs)
        return _validate_action(action)
    return {
        **common,
        "action": "dispatch_parallel",
        "instruction_file": str(THIN_STAGE1D_RUNTIME),
        "candidates": candidates,
        "candidate_titles": _abuse_candidate_titles(output_dir, candidates),
        "receipts": receipts,
    }


_ABUSE_TITLE_MAX = 60


def _abuse_candidate_titles(output_dir: Path, candidates: list[str]) -> dict[str, str]:
    """``{AC-ID: short title}`` from the matcher sidecar, for dispatch labels.

    The verifier fan-out is otherwise a column of bare ids in the agent list.
    Titles come from the catalogue via ``.abuse-case-matches.json``; they are
    truncated here so one long scenario name cannot push the console line into
    a wrap. Best-effort: a missing or unreadable sidecar simply yields no
    titles, and the dispatcher falls back to the id alone.
    """
    try:
        doc = json.loads((output_dir / ".abuse-case-matches.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    wanted = set(candidates)
    titles: dict[str, str] = {}
    for match in doc.get("matches") or []:
        if not isinstance(match, dict):
            continue
        ac_id = match.get("abuse_case_id")
        title = str(match.get("title") or "").strip()
        if ac_id in wanted and title:
            titles[ac_id] = title if len(title) <= _ABUSE_TITLE_MAX else title[: _ABUSE_TITLE_MAX - 1].rstrip() + "…"
    return titles


_YAML_SCHEMA_EXIT = 5


def _schema_failure_detail(message: str, limit: int = 700) -> str:
    """Keep the validator's `INVALID:` lines within the action `reason` cap."""
    invalid = [line.strip() for line in message.splitlines() if line.strip().startswith("INVALID")]
    detail = "; ".join(invalid) or " ".join(message.split())
    return detail if len(detail) <= limit else detail[: limit - 1].rstrip() + "…"


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
        # The rebuild folds the verified chains into threat-model.yaml.
        # build_threat_model_yaml.py writes the yaml BEFORE it schema-validates,
        # so exit 5 ("FATAL: schema validation failed") leaves an INVALID model
        # on disk — tolerating it as a receipt let a run carry that yaml into
        # Stage 2 and into the delivered report. Its soft exits (2 missing
        # output dir, 3 missing intermediate, 4 absent carry-forward field) all
        # abort before the write and leave the previous yaml intact, so those
        # stay best-effort.
        try:
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
                fatal_exit_codes=(_YAML_SCHEMA_EXIT,),
            )
        except ControllerError as exc:
            raise ControllerError(
                "threat-model.yaml rebuild failed schema validation during abuse-case "
                "finalization; the yaml on disk is invalid and must not reach Stage 2: "
                + _schema_failure_detail(str(exc)),
                exc.exit_code,
            ) from exc
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
        "stage": "stage1d",
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
    blocked_path = output_dir / ".compose-blocked.json"

    def _block(step: str, detail: str) -> bool:
        """Persist WHY the compose tail stopped, then report failure.

        Every one of this function's exit points used to collapse into a bare
        ``False`` that the caller labelled "Stage-2 render fragments
        incomplete" — even though the fragment check is only the FIRST of a
        dozen. On juice-shop 2026-07-24 both required fragments were present
        and correct; the tail aborted in a mitigation helper, and the bogus
        receipt made the orchestrator discard two finished specialist renders
        and re-dispatch the full renderer for ~9 minutes to redo work already
        on disk. Recording the real step and its stderr makes that
        misdiagnosis impossible."""
        try:
            blocked_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "blocked_at": datetime.now(timezone.utc).isoformat(),
                        "step": step,
                        "detail": detail[-2000:],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        return False

    try:
        blocked_path.unlink()
    except (FileNotFoundError, OSError):
        pass

    frag_dir = output_dir / ".fragments"
    missing = [name for name in _REQUIRED_RENDER_FRAGMENTS if not (frag_dir / name).is_file()]
    if missing:
        return _block("required-fragments", f"missing render fragment(s): {', '.join(missing)}")
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
            if proc.returncode != 0:
                _run.last_error = (  # type: ignore[attr-defined]
                    f"exit {proc.returncode}\n{(proc.stderr or proc.stdout or '').strip()}"
                )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError) as exc:
            _run.last_error = f"{type(exc).__name__}: {exc}"  # type: ignore[attr-defined]
            return False

    _run.last_error = ""  # type: ignore[attr-defined]

    def _step(script: str, *args: str) -> bool:
        """Run a mandatory tail step, recording the real blocker on failure."""
        if _run(str(SCRIPT_DIR / script), *args):
            return True
        return _block(script, _run.last_error)  # type: ignore[attr-defined]

    # Complete the canonical mitigation cards before any fragment or report is
    # rendered. The normal skill path already ran these idempotent helpers; the
    # thin-runtime recovery path can reach this point after a turn cut-off, so
    # it must not bypass the developer-actionability contract.
    if not _step("emit_general_mitigation_titles.py", str(output_dir)):
        return False
    # Scanner findings carry only a one-line mitigation_title; synthesise a
    # structured remediation block (steps + verification) from the check library
    # before hydration so the P1/P2 quality gate is satisfiable on the recovery
    # path too (mirrors the auto-emitter pass ordering).
    if not _step("backfill_scanner_remediation.py", str(output_dir)):
        return False
    if not _step("hydrate_mitigation_details.py", str(output_dir)):
        return False
    if not _step("validate_mitigation_quality.py", str(output_dir)):
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
    # ms-verdict.json joins the floor: compose HARD-fails without it, and it is
    # the one MANDATORY MS fragment neither prepare_stage2 nor this pass used to
    # regenerate — so an MS-renderer cut-off before its first Write forced a
    # full re-dispatch. The generator is idempotent and preserves a
    # renderer-authored (richer) copy already on disk.
    _run(
        str(SCRIPT_DIR / "pregenerate_fragments.py"),
        str(output_dir),
        "--only",
        "ms-ai-exposure.json,ms-critical-attack-tree.json,ms-verdict.json",
    )
    if not _step("compose_threat_model.py", "--output-dir", str(output_dir), "--strict"):
        return False
    if not md.is_file():
        return _block("compose_threat_model.py", "compose returned 0 but threat-model.md is absent")
    # Carry the rendered verdict into the semantic model before cleanup reaps
    # `.fragments/`, so every consumer can state the assessment's conclusion.
    _run(str(SCRIPT_DIR / "emit_verdict_to_model.py"), str(output_dir))
    _run(str(SCRIPT_DIR / "apply_prose_fixes.py"), str(md))
    _run(str(SCRIPT_DIR / "qa_checks.py"), "autofix", str(md), repo_root or str(output_dir))
    try:
        (output_dir / ".appsec-checkpoint").write_text(
            f"phase=11 status=completed timestamp={datetime.now(timezone.utc).isoformat()}\n",
            encoding="utf-8",
        )
        _append_event(output_dir, "PHASE_END", "[Phase 11/11] Finalization (controller compose)")
    except OSError as exc:
        return _block("checkpoint-write", f"{type(exc).__name__}: {exc}")
    return md.is_file()


# Which deterministic yaml-derived exports a run can request, and the script
# that produces each. Both take the same `--threat-model` / `--output` pair.
# `pentest-tasks.yaml` is deliberately NOT here: it needs repo-root/format/
# target arguments and a follow-up validate_intermediate pass, so it keeps the
# analyst as its only producer until that flow gets the same treatment.
_YAML_DERIVED_EXPORTS: tuple[tuple[str, str, str], ...] = (
    ("write_sarif", "export_sarif.py", "threat-model.sarif.json"),
    ("write_threatdragon", "export_threat_dragon.py", "threat-model.threatdragon.json"),
)


def _export_if_configured(output_dir: Path, cfg: dict[str, Any]) -> None:
    """Produce the deterministic yaml-derived exports the run asked for.

    ``--sarif`` and ``--threatdragon`` are pure functions of
    ``threat-model.yaml``, but their only trigger was Phase-11 substeps 7-9 of
    the threat-analyst (``agents/phases/phase-group-finalization.md``). The thin
    runtime caps Analyst-B at ``STAGE1_PHASE_LIMIT=10b`` and hands substeps 4+
    to Stage 2, where nothing owns them — so a ``--threatdragon`` run promised
    the artefact in its pre-flight, produced nothing, and the completion summary
    dropped the line without a warning (juice-shop 2026-08-02). ``run-headless.sh``
    already carried exactly this backstop, but only for the headless path.

    Anchoring it here, in the mandatory re-entrant ``next`` gate that reads the
    durable on-disk config, makes the artefact independent of whether an LLM
    step ran — the same reasoning as ``_stamp_if_configured`` below, which it
    runs before so the stamped copy set includes the exports. Idempotent (an
    existing artefact is left alone) and fail-safe (never raises into ``next``).
    """
    if not (output_dir / "threat-model.yaml").is_file():
        return
    for key, script, basename in _YAML_DERIVED_EXPORTS:
        if not cfg.get(key):
            continue
        target = output_dir / basename
        if target.is_file():
            continue
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_DIR / script),
                    "--threat-model",
                    str(output_dir / "threat-model.yaml"),
                    "--output",
                    str(target),
                ],
                cwd=str(SCRIPT_DIR),
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and target.is_file():
            _append_event(output_dir, "EXPORT_BACKSTOP", f"{script} wrote {basename} from threat-model.yaml")


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
            # Name the step that actually blocked. "fragments incomplete" is
            # reserved for the required-fragment existence check; any other
            # blocker (a mitigation gate, a strict-compose failure) reports
            # itself, so the operator is not sent to inspect a fragment set
            # that was complete all along.
            try:
                blocked = json.loads((output_dir / ".compose-blocked.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                blocked = {}
            step = str(blocked.get("step") or "") if isinstance(blocked, dict) else ""
            if step == "required-fragments":
                receipt = f"Stage-2 render fragments incomplete; retry {retry_count}/2"
            elif step:
                receipt = f"Stage-2 compose blocked at {step}; retry {retry_count}/2 (see .compose-blocked.json)"
            else:
                receipt = f"Stage-2 compose did not complete; retry {retry_count}/2"
            return {
                **common,
                "action": "dispatch_agent",
                "stage": "stage2",
                "instruction_file": str(THIN_STAGE2_RUNTIME),
                "receipts": [receipt],
            }
    for name in (".inline-shortcut-retry-count", ".inline-shortcut-repair-plan.json", ".compose-blocked.json"):
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
    # Deterministic export backstop: the requested yaml-derived artefacts must
    # not depend on whether the LLM finalization ran its substep. Before the
    # stamp, so the stamped copy set includes them.
    _export_if_configured(output_dir, cfg)
    # Deterministic slug-stamp backstop: the run is complete, so emit the
    # postfix-stamped deliverable copy set here rather than relying on the
    # trailing LLM-driven skill block (which a compaction-resumed orchestrator
    # can skip, and whose $SLUG guard does not survive compaction anyway).
    _stamp_if_configured(output_dir, cfg)
    try:
        (output_dir / ".appsec-checkpoint").unlink()
    except (FileNotFoundError, OSError):
        pass
    return {
        **common,
        "action": "complete",
        "stage": "complete",
    }


def _split_remainder(values: list[str]) -> list[str]:
    return values[1:] if values and values[0] == "--" else values


def _aggregate_issues_on_abort(output_dir: Any, reason: str, repo_root: Any = None) -> None:
    """Populate .run-issues.json when the controller aborts the run.

    aggregate_run_issues.py has exactly one call site: the Completion step in
    SKILL-impl.md. An aborted run never reaches it, so the very runs that most
    need a diagnostic bundle are the ones that produce none -- `report-error`
    and `diagnose-bundle` then read a stale file from a previous run, or none at
    all. The 2026-07-20 juice-shop abort left `.run-issues.json` reporting a
    clean run for a run that died without a deliverable.

    Best-effort in every direction: no output dir, an unreadable one, or an
    aggregator failure must never mask the real abort reason.
    """
    if not output_dir:
        return
    path: Path | None = None
    try:
        path = Path(output_dir)
        if not path.is_dir():
            return
        if not repo_root:
            try:
                config = json.loads((path / ".skill-config.json").read_text(encoding="utf-8"))
                repo_root = config.get("repo_root")
            except (OSError, ValueError, AttributeError):
                repo_root = None
        _append_event(path, "RUN_ABORTED", _abort_event_detail(reason), level="WARN")
        command = [sys.executable, str(SCRIPT_DIR / "aggregate_run_issues.py"), str(path)]
        if repo_root and Path(repo_root).is_dir():
            command.extend(["--repo-root", str(repo_root)])
        subprocess.run(
            command,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except Exception:
        pass
    finally:
        if path is not None:
            try:
                from agent_logger import clear_terminal_active_tool_calls  # noqa: PLC0415

                clear_terminal_active_tool_calls(path)
            except Exception:
                pass


#: Boundaries that run after a semantic producer returned and its output was
#: accepted. Each is a point where the call-scoped telemetry surfaces must
#: already agree about the dispatch that just closed.
_SEMANTIC_RETURN_COMMANDS = frozenset(
    {
        "context-v2-post-recon",
        "context-v2-post-actors",
        "context-v2-post-architecture",
        "context-v2-post-boundary",
        "context-v2-prepare-stride",
        "context-v2-post-stride",
        "context-v2-post-merge",
        "context-v2-post-evidence",
        "context-v2-post-triage",
        "context-v2-finalize",
        "finalize-abuse",
    }
)


def _check_returned_call_telemetry(output_dir: Path) -> None:
    """Report where accepted output, lifecycle, budget, and stage stats disagree.

    Observational by default: a mismatch is a telemetry defect, not a reason to
    stop a production run. ``APPSEC_TELEMETRY_STRICT=1`` aborts instead, so an
    acceptance run cannot pass on evidence its own producers contradict.
    """
    try:
        findings = telemetry_consistency.check_returned_calls(output_dir)
    except Exception as exc:  # noqa: BLE001 — an observational check never stops a run
        if telemetry_consistency.strict_enabled():
            raise ControllerError(f"telemetry consistency check failed: {exc}") from exc
        return
    for finding in findings:
        _append_event(output_dir, "TELEMETRY_MISMATCH", telemetry_consistency.format_detail(finding), level="WARN")
    if findings and telemetry_consistency.strict_enabled():
        raise ControllerError(
            "telemetry mismatch at a semantic boundary: "
            + "; ".join(f"{finding['code']} on {finding['job_id']}" for finding in findings)
        )


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
    post_stage1a_parser = sub.add_parser("post-stage1a")
    post_stage1a_parser.add_argument("--output-dir", required=True)
    finalize_stage1b_parser = sub.add_parser("finalize-stage1b")
    finalize_stage1b_parser.add_argument("--output-dir", required=True)
    post_stage1c_parser = sub.add_parser("post-stage1c")
    post_stage1c_parser.add_argument("--output-dir", required=True)
    prepare_abuse_parser = sub.add_parser("prepare-abuse")
    prepare_abuse_parser.add_argument("--output-dir", required=True)
    finalize_abuse_parser = sub.add_parser("finalize-abuse")
    finalize_abuse_parser.add_argument("--output-dir", required=True)
    prepare_stage2_parser = sub.add_parser("prepare-stage2")
    prepare_stage2_parser.add_argument("--output-dir", required=True)
    context_v2_begin_parser = sub.add_parser("context-v2-begin")
    context_v2_begin_parser.add_argument("--output-dir", required=True)
    context_v2_post_recon_parser = sub.add_parser("context-v2-post-recon")
    context_v2_post_recon_parser.add_argument("--output-dir", required=True)
    context_v2_post_actors_parser = sub.add_parser("context-v2-post-actors")
    context_v2_post_actors_parser.add_argument("--output-dir", required=True)
    context_v2_post_architecture_parser = sub.add_parser("context-v2-post-architecture")
    context_v2_post_architecture_parser.add_argument("--output-dir", required=True)
    context_v2_post_boundary_parser = sub.add_parser("context-v2-post-boundary")
    context_v2_post_boundary_parser.add_argument("--output-dir", required=True)
    context_v2_prepare_stride_parser = sub.add_parser("context-v2-prepare-stride")
    context_v2_prepare_stride_parser.add_argument("--output-dir", required=True)
    context_v2_post_stride_parser = sub.add_parser("context-v2-post-stride")
    context_v2_post_stride_parser.add_argument("--output-dir", required=True)
    context_v2_post_merge_parser = sub.add_parser("context-v2-post-merge")
    context_v2_post_merge_parser.add_argument("--output-dir", required=True)
    context_v2_post_evidence_parser = sub.add_parser("context-v2-post-evidence")
    context_v2_post_evidence_parser.add_argument("--output-dir", required=True)
    context_v2_post_triage_parser = sub.add_parser("context-v2-post-triage")
    context_v2_post_triage_parser.add_argument("--output-dir", required=True)
    context_v2_finalize_parser = sub.add_parser("context-v2-finalize")
    context_v2_finalize_parser.add_argument("--output-dir", required=True)
    verify_receipts_parser = sub.add_parser("verify-receipts")
    verify_receipts_parser.add_argument("--output-dir", required=True)
    verify_receipts_parser.add_argument(
        "--receipt", nargs=2, action="append", required=True, metavar=("PATH", "SHA256")
    )
    next_parser = sub.add_parser("next")
    next_parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)

    try:
        if args.command in _SEMANTIC_RETURN_COMMANDS:
            _check_returned_call_telemetry(Path(args.output_dir))
        if args.command == "route":
            action = route(_split_remainder(args.arguments))
        elif args.command == "prepare":
            action = prepare(
                _split_remainder(args.arguments),
                force=args.force,
            )
        elif args.command == "post-stage1":
            action = post_stage1(Path(args.output_dir))
        elif args.command == "post-stage1a":
            action = post_stage1a(Path(args.output_dir))
        elif args.command == "finalize-stage1b":
            action = finalize_stage1b(Path(args.output_dir))
        elif args.command == "post-stage1c":
            action = post_stage1c(Path(args.output_dir))
        elif args.command == "prepare-abuse":
            action = prepare_abuse(Path(args.output_dir))
        elif args.command == "finalize-abuse":
            action = finalize_abuse(Path(args.output_dir))
        elif args.command == "prepare-stage2":
            action = prepare_stage2(Path(args.output_dir))
        elif args.command == "context-v2-begin":
            action = context_v2_begin(Path(args.output_dir))
        elif args.command == "context-v2-post-recon":
            action = context_v2_post_recon(Path(args.output_dir))
        elif args.command == "context-v2-post-actors":
            action = context_v2_post_actors(Path(args.output_dir))
        elif args.command == "context-v2-post-architecture":
            action = context_v2_post_architecture(Path(args.output_dir))
        elif args.command == "context-v2-post-boundary":
            action = context_v2_post_boundary(Path(args.output_dir))
        elif args.command == "context-v2-prepare-stride":
            action = context_v2_prepare_stride(Path(args.output_dir))
        elif args.command == "context-v2-post-stride":
            action = context_v2_post_stride(Path(args.output_dir))
        elif args.command == "context-v2-post-merge":
            action = context_v2_post_merge(Path(args.output_dir))
        elif args.command == "context-v2-post-evidence":
            action = context_v2_post_evidence(Path(args.output_dir))
        elif args.command == "context-v2-post-triage":
            action = context_v2_post_triage(Path(args.output_dir))
        elif args.command == "context-v2-finalize":
            action = context_v2_finalize(Path(args.output_dir))
        elif args.command == "verify-receipts":
            action = verify_receipt_hashes(Path(args.output_dir), [tuple(pair) for pair in args.receipt])
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
        _aggregate_issues_on_abort(
            getattr(args, "output_dir", None),
            str(exc),
            getattr(args, "repo_root", None),
        )
    return _emit(action)


if __name__ == "__main__":
    raise SystemExit(main())
