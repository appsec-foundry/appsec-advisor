#!/usr/bin/env python3
"""Validate and resolve the Stage-1 context routing catalog.

The YAML catalog is the human configuration surface. Runtime paths, schemas,
projectors, and hard safety limits live in the separate plugin-owned bindings
file so a human never has to configure implementation details. Resolution
explains every context-v2 action and binds the subset whose migration is active.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from _atomic_io import atomic_write_json
from jsonschema import Draft202012Validator

SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_ROOT = SCRIPT_DIR.parent
CATALOG_PATH = PLUGIN_ROOT / "data" / "context-routing-catalog.yaml"
BINDINGS_PATH = PLUGIN_ROOT / "data" / "context-routing-bindings.json"
CATALOG_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "context-routing-catalog.schema.json"
BINDINGS_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "context-routing-bindings.schema.json"
PLAN_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "context-effective-plan.schema.json"
PLAN_RECEIPT_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "context-effective-plan-receipt.schema.json"
PLAN_NAME = ".context-routing-plan.json"
PLAN_RECEIPT_NAME = ".context-routing-plan.receipt.json"
MAX_PLAN_BYTES = 4_194_304
PLAN_SCHEMA_ID = "schemas/context-effective-plan.schema.json#v1"


class ContextRoutingError(RuntimeError):
    """Raised when catalog semantics or a resolved delivery are unsafe."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _action_basis(action: dict[str, Any]) -> dict[str, Any]:
    """Remove the effective-plan self-reference before hashing an action."""
    basis = copy.deepcopy(action)
    basis.pop("context_plan", None)
    for job in basis.get("dispatch_jobs", []):
        job.pop("context_delivery_ids", None)
    basis["artifact_receipts"] = [
        receipt for receipt in basis.get("artifact_receipts", []) if receipt.get("artifact_path") != PLAN_NAME
    ]
    if not basis.get("artifact_receipts"):
        basis.pop("artifact_receipts", None)
    return basis


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContextRoutingError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContextRoutingError(f"{path.name} must contain an object")
    return value


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ContextRoutingError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContextRoutingError(f"{path.name} must contain a mapping")
    return value


def _validate_schema(value: dict[str, Any], schema_path: Path, label: str) -> None:
    schema = _load_json(schema_path)
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda item: list(item.absolute_path))
    if errors:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or 'root'}: {error.message}" for error in errors[:5]
        )
        raise ContextRoutingError(f"{label} schema validation failed: {details}")


def load_catalog_contracts(
    *,
    catalog_path: Path = CATALOG_PATH,
    bindings_path: Path = BINDINGS_PATH,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Load structurally valid catalog and internal bindings with byte hashes."""
    catalog_bytes = catalog_path.read_bytes()
    bindings_bytes = bindings_path.read_bytes()
    catalog = _load_yaml(catalog_path)
    bindings = _load_json(bindings_path)
    _validate_schema(catalog, CATALOG_SCHEMA_PATH, "context routing catalog")
    _validate_schema(bindings, BINDINGS_SCHEMA_PATH, "context routing bindings")
    return catalog, bindings, _sha256(catalog_bytes), _sha256(bindings_bytes)


def _unique_index(values: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        item_id = value["id"]
        if item_id in result:
            raise ContextRoutingError(f"duplicate {label} id: {item_id}")
        result[item_id] = value
    return result


def _safe_template(template: str) -> None:
    if "\\" in template or "://" in template or template.startswith("/"):
        raise ContextRoutingError(f"unsafe context artifact template: {template!r}")
    placeholders = set(re.findall(r"\{([^{}]+)\}", template))
    if placeholders - {"component_id", "candidate_id"}:
        raise ContextRoutingError(f"unknown context artifact placeholder in {template!r}")
    rendered = template.replace("{component_id}", "component").replace("{candidate_id}", "candidate")
    if any(part in {"", ".", ".."} for part in Path(rendered).parts):
        raise ContextRoutingError(f"unsafe context artifact template: {template!r}")
    if any(token in rendered for token in ("*", "?", "[", "]")):
        raise ContextRoutingError(f"context artifact templates must be literal: {template!r}")


def _validate_plugin_path(plugin_root: Path, relative: str) -> None:
    _safe_template(relative)
    lexical = plugin_root / relative
    try:
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(plugin_root.resolve())
    except (OSError, ValueError) as exc:
        raise ContextRoutingError(f"plugin context path is missing or escapes the plugin: {relative!r}") from exc
    if not resolved.is_file():
        raise ContextRoutingError(f"plugin context path is not a file: {relative!r}")


def _check_dependency_cycles(contexts: dict[str, dict[str, Any]]) -> None:
    visiting: set[str] = set()
    complete: set[str] = set()

    def visit(context_id: str) -> None:
        if context_id in complete:
            return
        if context_id in visiting:
            raise ContextRoutingError(f"context dependency cycle contains {context_id}")
        visiting.add(context_id)
        for dependency in contexts[context_id]["depends_on"]:
            if dependency not in contexts:
                raise ContextRoutingError(f"unknown dependency {dependency!r} for context {context_id!r}")
            visit(dependency)
        visiting.remove(context_id)
        complete.add(context_id)

    for context_id in contexts:
        visit(context_id)


def validate_catalog_semantics(
    catalog: dict[str, Any],
    bindings: dict[str, Any],
    *,
    semantic_roles: dict[str, dict[str, Any]],
    model_keys: dict[str, str],
    plugin_root: Path = PLUGIN_ROOT,
) -> None:
    """Bind the human catalog to the closed runtime registries."""
    if catalog["catalog_id"] != bindings["catalog_id"]:
        raise ContextRoutingError("catalog and runtime bindings use different catalog_id values")

    categories = _unique_index(catalog["categories"], "category")
    agents = _unique_index(catalog["agents"], "agent")
    contexts = _unique_index(catalog["contexts"], "context")
    assignments = _unique_index(catalog["assignments"], "assignment")
    agent_bindings = _unique_index(bindings["agents"], "agent binding")
    context_bindings = _unique_index(bindings["contexts"], "context binding")

    if set(agents) != set(agent_bindings):
        raise ContextRoutingError("human agent catalog and runtime agent bindings do not match")
    if set(contexts) != set(context_bindings):
        raise ContextRoutingError("human context catalog and runtime context bindings do not match")

    context_v2_bindings = {
        binding["semantic_role"]: binding for binding in agent_bindings.values() if binding["runtime"] == "context_v2"
    }
    if set(context_v2_bindings) != set(semantic_roles):
        raise ContextRoutingError("context-v2 agent bindings drifted from the semantic-role registry")
    for role, binding in context_v2_bindings.items():
        expected_type = semantic_roles[role]["agent"]
        if binding["id"] != role or binding["agent_type"] != expected_type:
            raise ContextRoutingError(f"agent binding does not match semantic role {role!r}")
        if binding["model_setting"] != model_keys.get(role):
            raise ContextRoutingError(f"agent binding model setting does not match semantic role {role!r}")
    for context in contexts.values():
        if context["category"] not in categories:
            raise ContextRoutingError(f"unknown category {context['category']!r} for context {context['id']!r}")

    seen_pairs: set[tuple[str, str]] = set()
    for assignment in assignments.values():
        context_id = assignment["context"]
        if context_id not in contexts:
            raise ContextRoutingError(f"assignment {assignment['id']!r} references unknown context {context_id!r}")
        delivery = assignment["delivery"]
        importance = assignment["importance"]
        if delivery in {"required", "forbidden"} and importance != "essential":
            raise ContextRoutingError(f"{delivery} assignment {assignment['id']!r} must be essential")
        if delivery == "optional" and importance == "essential":
            raise ContextRoutingError(f"optional assignment {assignment['id']!r} cannot be essential")
        target = assignment["applies_to"]
        context_scope = contexts[context_id]["scope"]
        expected_target = {
            "one_component": "current_component",
            "one_candidate": "current_candidate",
        }.get(context_scope)
        if expected_target and target != expected_target:
            raise ContextRoutingError(
                f"assignment {assignment['id']!r} must target {expected_target!r} for {context_scope!r} context"
            )
        for agent_id in assignment["agents"]:
            if agent_id not in agents:
                raise ContextRoutingError(f"assignment {assignment['id']!r} references unknown agent {agent_id!r}")
            pair = (agent_id, context_id)
            if pair in seen_pairs:
                raise ContextRoutingError(f"duplicate or contradictory assignment for {agent_id!r} and {context_id!r}")
            seen_pairs.add(pair)
            if target == "current_component":
                if agents[agent_id]["scope"] != "one_component" or contexts[context_id]["scope"] != "one_component":
                    raise ContextRoutingError(
                        f"current-component assignment {assignment['id']!r} requires component-scoped agent and context"
                    )
            if target == "current_candidate":
                if agents[agent_id]["scope"] != "one_candidate" or contexts[context_id]["scope"] != "one_candidate":
                    raise ContextRoutingError(
                        f"current-candidate assignment {assignment['id']!r} requires candidate-scoped agent and context"
                    )

    positive_contexts = {
        assignment["context"] for assignment in assignments.values() if assignment["delivery"] != "forbidden"
    }
    profiles = bindings["limit_profiles"]
    for field in ("trust_classes", "sensitivity_classes"):
        classified = [context_id for values in bindings[field].values() for context_id in values]
        if len(classified) != len(set(classified)) or set(classified) != set(context_bindings):
            raise ContextRoutingError(f"{field} must classify every context exactly once")
    for context_id, binding in context_bindings.items():
        if binding["limit_profile"] not in profiles:
            raise ContextRoutingError(f"unknown limit profile for context {context_id!r}")
        source = binding["source"]
        if source["kind"] == "output_artifact":
            _safe_template(source["artifact_pattern"])
        elif source["kind"] == "plugin_artifact":
            _validate_plugin_path(plugin_root, source["plugin_path"])
        expected_source = {
            "declared": "output_artifact",
            "implicit": "output_artifact",
            "direct-source": "direct_source",
            "scalar": "scalar",
        }
        if (
            binding["delivery"] in expected_source
            and source["kind"] != expected_source[binding["delivery"]]
            and not (context_id not in positive_contexts and source["kind"] == "plugin_registry")
        ):
            raise ContextRoutingError(f"context {context_id!r} has incompatible delivery and source kinds")
        if binding["delivery"] == "plugin-owned" and source["kind"] not in {"plugin_artifact", "plugin_registry"}:
            raise ContextRoutingError(f"plugin-owned context {context_id!r} has an unsafe source kind")
        if binding.get("enforcement", "shadow") == "active":
            if context_id not in positive_contexts:
                raise ContextRoutingError(f"active context {context_id!r} has no positive human assignment")
            if binding["delivery"] not in {"declared", "scalar"}:
                raise ContextRoutingError(f"active context {context_id!r} must use declared or scalar delivery")
            if source["kind"] not in {"output_artifact", "scalar"}:
                raise ContextRoutingError(f"active context {context_id!r} must use a receiptable source")
        for agent_id, delivery in binding.get("delivery_overrides", {}).items():
            if agent_id not in agents:
                raise ContextRoutingError(f"context {context_id!r} has an override for unknown agent {agent_id!r}")
            if delivery not in {"declared", "implicit", "direct-source", "plugin-owned", "scalar"}:
                raise ContextRoutingError(f"context {context_id!r} has an invalid delivery override")
    _check_dependency_cycles(context_bindings)


def _resolve_output_path(output_root: Path, relative: str, *, require_file: bool) -> Path:
    _safe_template(relative)
    lexical = output_root / relative
    try:
        resolved = lexical.resolve(strict=require_file)
        resolved.relative_to(output_root.resolve())
    except (OSError, ValueError) as exc:
        raise ContextRoutingError(f"context artifact is missing or escapes the output directory: {relative!r}") from exc
    if require_file and not resolved.is_file():
        raise ContextRoutingError(f"context artifact is not a file: {relative!r}")
    return resolved


def _render_artifact(pattern: str, component_id: str | None, candidate_id: str | None = None) -> str:
    if "{component_id}" in pattern:
        if not component_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", component_id):
            raise ContextRoutingError(f"component-scoped context requires a valid component id for {pattern!r}")
        pattern = pattern.replace("{component_id}", component_id)
    if "{candidate_id}" in pattern:
        if not candidate_id or not re.fullmatch(r"(?:AC-T|AC|ORG-AC|REPO-AC)-[0-9]{3,}", candidate_id):
            raise ContextRoutingError(f"candidate-scoped context requires a valid candidate id for {pattern!r}")
        pattern = pattern.replace("{candidate_id}", candidate_id)
    return pattern


def _counts(payload: bytes, record_count: int | None = None) -> dict[str, int]:
    line_count = payload.count(b"\n") + (1 if payload and not payload.endswith(b"\n") else 0)
    return {
        "byte_count": len(payload),
        "estimated_tokens": (len(payload) + 3) // 4,
        "item_count": record_count if record_count is not None else (1 if payload else 0),
        "line_count": line_count,
    }


def _enforce_limits(context_id: str, counts: dict[str, int], limits: dict[str, int]) -> None:
    mapping = {
        "byte_count": "max_bytes",
        "estimated_tokens": "max_tokens",
        "item_count": "max_items",
        "line_count": "max_lines",
    }
    for count_key, limit_key in mapping.items():
        if counts[count_key] > limits[limit_key]:
            raise ContextRoutingError(
                f"context {context_id!r} exceeds {limit_key}: {counts[count_key]} > {limits[limit_key]}"
            )


def _source_receipt(
    payload: bytes,
    binding: dict[str, Any],
    limits: dict[str, int],
    *,
    artifact_path: str | None = None,
    plugin_path: str | None = None,
    action_receipt: dict[str, Any] | None = None,
    validation_status: str,
) -> dict[str, Any]:
    actual_sha = _sha256(payload)
    record_count = None
    if action_receipt is not None:
        if action_receipt["sha256"] != actual_sha:
            raise ContextRoutingError(f"action receipt is stale for {artifact_path!r}")
        if action_receipt["schema_id"] != binding["contract"]:
            raise ContextRoutingError(f"action receipt contract does not match context {binding['id']!r}")
        record_count = action_receipt["record_count"]
    counts = _counts(payload, record_count)
    _enforce_limits(binding["id"], counts, limits)
    result: dict[str, Any] = {
        "sha256": actual_sha,
        **counts,
        "schema_id": binding["contract"],
        "validation_status": validation_status,
    }
    if artifact_path is not None:
        result["artifact_path"] = artifact_path
    if plugin_path is not None:
        result["plugin_path"] = plugin_path
    return result


def _failure_behavior(delivery: str) -> str:
    return {"required": "abort", "optional": "continue_with_diagnostic", "forbidden": "not_applicable"}[delivery]


def _enforcement_disclosures(binding: dict[str, Any], *extra: str) -> list[str]:
    mode = "plan-enforced" if binding.get("enforcement", "shadow") == "active" else "shadow-only"
    return [*extra, mode]


def _delivery_base(
    *,
    action_id: str,
    action_sha: str,
    job: dict[str, Any],
    agent: dict[str, Any],
    context: dict[str, Any],
    category: dict[str, Any],
    assignment: dict[str, Any],
    binding: dict[str, Any],
    trust: str,
    sensitivity: str,
    catalog_sha: str,
    bindings_sha: str,
) -> dict[str, Any]:
    job_id = job["job_id"]
    context_id = context["id"]
    delivery_id = f"{job_id}:{_sha256(context_id.encode())[:12]}"
    result: dict[str, Any] = {
        "delivery_id": delivery_id,
        "action_id": action_id,
        "job_id": job_id,
        "agent_id": agent["id"],
        "agent_name": agent["name"],
        "context_id": context_id,
        "context_name": context["name"],
        "category_id": category["id"],
        "category_name": category["name"],
        "assignment_id": assignment["id"],
        "producer": binding["producer"],
        "projector": binding["projector"],
        "scope": context["scope"],
        "applies_to": assignment["applies_to"],
        "trust": trust,
        "sensitivity": sensitivity,
        "delivery": assignment["delivery"],
        "importance": assignment["importance"],
        "failure_behavior": _failure_behavior(assignment["delivery"]),
        "reason": assignment["reason"],
        "freshness": {
            "catalog_sha256": catalog_sha,
            "bindings_sha256": bindings_sha,
            "action_sha256": action_sha,
        },
    }
    if job.get("component_id") is not None:
        result["component_id"] = job["component_id"]
    if job.get("candidate_id") is not None:
        result["candidate_id"] = job["candidate_id"]
    return result


def _resolve_delivery(
    base: dict[str, Any],
    *,
    action: dict[str, Any],
    job: dict[str, Any],
    assignment: dict[str, Any],
    binding: dict[str, Any],
    output_root: Path,
    plugin_root: Path,
    limits: dict[str, int],
    action_receipts: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    delivery = assignment["delivery"]
    source = binding["source"]
    delivery_mode = binding.get("delivery_overrides", {}).get(job["semantic_role"], binding["delivery"])
    inputs = set(job.get("input_artifacts", []))

    if delivery == "forbidden":
        if source["kind"] == "output_artifact":
            artifact = _render_artifact(source["artifact_pattern"], job.get("component_id"), job.get("candidate_id"))
            if artifact in inputs:
                raise ContextRoutingError(f"forbidden context {binding['id']!r} is present in job {job['job_id']!r}")
        base.update(
            status="forbidden",
            match_reason="Core assignment withholds this context.",
            disclosures=["forbidden-by-core"],
        )
        return (
            base,
            {
                "code": "FORBIDDEN_CONTEXT_WITHHELD",
                "action_id": base["action_id"],
                "job_id": base["job_id"],
                "agent_id": base["agent_id"],
                "context_id": base["context_id"],
            },
            None,
        )

    if source["kind"] == "output_artifact":
        artifact = _render_artifact(source["artifact_pattern"], job.get("component_id"), job.get("candidate_id"))
        declared = artifact in inputs
        if delivery_mode == "declared" and not declared:
            if delivery == "required":
                raise ContextRoutingError(f"required context {binding['id']!r} is absent from job {job['job_id']!r}")
            base.update(
                status="omitted_optional",
                match_reason="The optional artifact is not declared for this job.",
                disclosures=_enforcement_disclosures(binding, "optional-missing"),
            )
            return (
                base,
                {
                    "code": "OPTIONAL_CONTEXT_ABSENT",
                    "action_id": base["action_id"],
                    "job_id": base["job_id"],
                    "agent_id": base["agent_id"],
                    "context_id": base["context_id"],
                },
                artifact,
            )
        path = output_root / artifact
        if not declared and delivery_mode == "implicit" and not path.is_file():
            if delivery == "required":
                raise ContextRoutingError(f"required implicit context {binding['id']!r} is missing")
            base.update(
                status="omitted_optional",
                match_reason="The optional implicit artifact is not present.",
                disclosures=_enforcement_disclosures(binding, "optional-missing"),
            )
            return (
                base,
                {
                    "code": "OPTIONAL_CONTEXT_ABSENT",
                    "action_id": base["action_id"],
                    "job_id": base["job_id"],
                    "agent_id": base["agent_id"],
                    "context_id": base["context_id"],
                },
                artifact if delivery_mode == "declared" else None,
            )
        resolved = _resolve_output_path(output_root, artifact, require_file=True)
        payload = resolved.read_bytes()
        action_receipt = action_receipts.get(artifact)
        if binding.get("enforcement", "shadow") == "active" and action_receipt is None:
            raise ContextRoutingError(
                f"active context {binding['id']!r} lacks a validated action receipt for {artifact!r}"
            )
        receipt = _source_receipt(
            payload,
            binding,
            limits,
            artifact_path=artifact,
            action_receipt=action_receipt,
            validation_status="action_validated" if action_receipt else "shadow_hashed",
        )
        base["freshness"]["source_sha256"] = receipt["sha256"]
        base.update(
            status="delivered" if declared else "observed_implicit",
            match_reason=(
                "The current action declares this exact artifact."
                if declared
                else "The current agent contract reads this artifact implicitly."
            ),
            source_receipt=receipt,
            disclosures=_enforcement_disclosures(binding),
        )
        return base, None, artifact if delivery_mode == "declared" else None

    if source["kind"] == "plugin_artifact":
        relative = source["plugin_path"]
        _validate_plugin_path(plugin_root, relative)
        payload = (plugin_root / relative).resolve().read_bytes()
        receipt = _source_receipt(
            payload,
            binding,
            limits,
            plugin_path=relative,
            validation_status="plugin_owned",
        )
        base["freshness"]["source_sha256"] = receipt["sha256"]
        base.update(
            status="observed_plugin_owned",
            match_reason="The agent contract selects this fixed plugin-owned artifact.",
            source_receipt=receipt,
            disclosures=_enforcement_disclosures(binding),
        )
        return base, None, None

    if source["kind"] == "scalar":
        values: dict[str, Any] = {}
        dispatch_values = action.get("dispatch_values", {})
        for field in source["scalar_fields"]:
            if field in job:
                values[field] = job[field]
            elif field in dispatch_values:
                values[field] = dispatch_values[field]
        if not values:
            if delivery == "required":
                raise ContextRoutingError(f"required scalar context {binding['id']!r} has no resolved values")
            base.update(
                status="omitted_optional",
                match_reason="No values are resolved for this optional setting.",
                disclosures=_enforcement_disclosures(binding, "optional-missing"),
            )
            return (
                base,
                {
                    "code": "OPTIONAL_CONTEXT_ABSENT",
                    "action_id": base["action_id"],
                    "job_id": base["job_id"],
                    "agent_id": base["agent_id"],
                    "context_id": base["context_id"],
                },
                None,
            )
        payload = _canonical_json_bytes(values)
        receipt = _source_receipt(payload, binding, limits, validation_status="scalar_canonical")
        base["freshness"]["source_sha256"] = receipt["sha256"]
        base.update(
            status="observed_scalar",
            match_reason="The controller resolved these bounded settings for this job.",
            source_receipt=receipt,
            disclosures=_enforcement_disclosures(binding),
        )
        return base, None, None

    base.update(
        status="legacy_unreceipted",
        match_reason="The current agent contract still owns this bounded read outside structured delivery.",
        disclosures=["legacy-unreceipted"],
    )
    return (
        base,
        {
            "code": "LEGACY_CONTEXT_UNRECEIPTED",
            "action_id": base["action_id"],
            "job_id": base["job_id"],
            "agent_id": base["agent_id"],
            "context_id": base["context_id"],
        },
        None,
    )


def _plan_paths(output_root: Path) -> tuple[Path, Path]:
    return output_root / PLAN_NAME, output_root / PLAN_RECEIPT_NAME


def reset_plan(output_root: Path) -> None:
    """Remove only the two controller-owned effective-plan files."""
    output_root = output_root.resolve()
    for path in _plan_paths(output_root):
        if path.exists() or path.is_symlink():
            if path.is_dir() and not path.is_symlink():
                raise ContextRoutingError(f"effective plan path is a directory: {path.name}")
            path.unlink()


def _validate_plan_receipt(plan_path: Path, receipt_path: Path) -> dict[str, Any]:
    plan = _load_json(plan_path)
    receipt = _load_json(receipt_path)
    _validate_schema(plan, PLAN_SCHEMA_PATH, "effective context plan")
    _validate_schema(receipt, PLAN_RECEIPT_SCHEMA_PATH, "effective context plan receipt")
    payload = plan_path.read_bytes()
    if _sha256(payload) != receipt["sha256"]:
        raise ContextRoutingError("effective context plan changed after its exact-byte receipt was written")
    if receipt["record_count"] != len(plan["deliveries"]):
        raise ContextRoutingError("effective context plan receipt has a stale delivery count")
    return plan


def _load_prior_plan(
    output_root: Path,
    *,
    catalog: dict[str, Any],
    catalog_sha: str,
    bindings_sha: str,
    run_key_sha: str,
) -> dict[str, Any]:
    plan_path, receipt_path = _plan_paths(output_root)
    if not plan_path.exists() and not receipt_path.exists():
        return {
            "schema_version": 1,
            "catalog_id": catalog["catalog_id"],
            "catalog_sha256": catalog_sha,
            "bindings_sha256": bindings_sha,
            "runtime_generation": "context-v2",
            "run_key_sha256": run_key_sha,
            "revision": 0,
            "actions": [],
            "deliveries": [],
            "diagnostics": [],
        }
    if not plan_path.is_file() or not receipt_path.is_file():
        raise ContextRoutingError("effective context plan and its receipt must exist together")
    plan = _validate_plan_receipt(plan_path, receipt_path)
    expected = (catalog["catalog_id"], catalog_sha, bindings_sha, run_key_sha)
    actual = (
        plan["catalog_id"],
        plan["catalog_sha256"],
        plan["bindings_sha256"],
        plan["run_key_sha256"],
    )
    if actual != expected:
        raise ContextRoutingError("effective context plan belongs to stale catalog, bindings, or run state")
    return plan


def _write_plan(output_root: Path, plan: dict[str, Any]) -> None:
    _validate_schema(plan, PLAN_SCHEMA_PATH, "effective context plan")
    payload = json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    if len(payload) > MAX_PLAN_BYTES:
        raise ContextRoutingError(f"effective context plan exceeds the {MAX_PLAN_BYTES}-byte cap")
    plan_path, receipt_path = _plan_paths(output_root)
    atomic_write_json(plan_path, plan, sort_keys=True)
    actual = plan_path.read_bytes()
    receipt = {
        "schema_version": 1,
        "artifact_path": PLAN_NAME,
        "schema_id": "schemas/context-effective-plan.schema.json#v1",
        "sha256": _sha256(actual),
        "record_count": len(plan["deliveries"]),
        "validation_status": "valid",
    }
    _validate_schema(receipt, PLAN_RECEIPT_SCHEMA_PATH, "effective context plan receipt")
    atomic_write_json(receipt_path, receipt, sort_keys=True)
    _validate_plan_receipt(plan_path, receipt_path)


def resolve_action(
    action: dict[str, Any],
    output_root: Path,
    *,
    semantic_roles: dict[str, dict[str, Any]],
    model_keys: dict[str, str],
    plugin_root: Path = PLUGIN_ROOT,
) -> dict[str, Any]:
    """Append one validated context-v2 action to the effective plan."""
    if action.get("action") not in {"dispatch_agent", "dispatch_parallel"}:
        raise ContextRoutingError("context resolution accepts only semantic dispatch actions")
    catalog, bindings, catalog_sha, bindings_sha = load_catalog_contracts()
    validate_catalog_semantics(
        catalog,
        bindings,
        semantic_roles=semantic_roles,
        model_keys=model_keys,
        plugin_root=plugin_root,
    )
    output_root = output_root.resolve()
    run_id = action.get("dispatch_values", {}).get("run_id")
    mode = action.get("mode")
    if not isinstance(run_id, str) or not run_id or mode not in {"full", "rebuild"}:
        raise ContextRoutingError("context-v2 effective plan requires a resolved full/rebuild run identity")
    run_key_sha = _sha256(_canonical_json_bytes({"mode": mode, "run_id": run_id}))
    plan = _load_prior_plan(
        output_root,
        catalog=catalog,
        catalog_sha=catalog_sha,
        bindings_sha=bindings_sha,
        run_key_sha=run_key_sha,
    )

    categories = _unique_index(catalog["categories"], "category")
    agents = _unique_index(catalog["agents"], "agent")
    contexts = _unique_index(catalog["contexts"], "context")
    agent_bindings = _unique_index(bindings["agents"], "agent binding")
    context_bindings = _unique_index(bindings["contexts"], "context binding")
    trust_by_context = {
        context_id: trust for trust, context_ids in bindings["trust_classes"].items() for context_id in context_ids
    }
    sensitivity_by_context = {
        context_id: sensitivity
        for sensitivity, context_ids in bindings["sensitivity_classes"].items()
        for context_id in context_ids
    }
    assignments_by_agent: dict[str, list[dict[str, Any]]] = {agent_id: [] for agent_id in agents}
    for assignment in catalog["assignments"]:
        for agent_id in assignment["agents"]:
            assignments_by_agent[agent_id].append(assignment)

    action_payload = _canonical_json_bytes(_action_basis(action))
    action_sha = _sha256(action_payload)
    job_ids = sorted(job["job_id"] for job in action["dispatch_jobs"])
    action_id = f"{action.get('stage', 'stage1')}:{_sha256('|'.join(job_ids).encode())[:16]}"
    action_record = {
        "action_id": action_id,
        "action_sha256": action_sha,
        "action_type": action["action"],
        "stage": action.get("stage", "stage1"),
        "job_ids": job_ids,
    }
    action_receipts = {receipt["artifact_path"]: receipt for receipt in action.get("artifact_receipts", [])}

    deliveries: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for job in action["dispatch_jobs"]:
        agent_id = job["semantic_role"]
        if agent_bindings[agent_id]["runtime"] != "context_v2":
            raise ContextRoutingError(f"action uses a non-context-v2 agent binding: {agent_id!r}")
        matched_declared: set[str] = set()
        delivered_bytes = 0
        assignments = sorted(assignments_by_agent[agent_id], key=lambda item: item["id"])
        limits = agent_bindings[agent_id]["limits"]
        if len(assignments) > limits["max_contexts"]:
            raise ContextRoutingError(f"agent {agent_id!r} exceeds its context-count cap")
        for assignment in assignments:
            context = contexts[assignment["context"]]
            category = categories[context["category"]]
            binding = context_bindings[context["id"]]
            base = _delivery_base(
                action_id=action_id,
                action_sha=action_sha,
                job=job,
                agent=agents[agent_id],
                context=context,
                category=category,
                assignment=assignment,
                binding=binding,
                trust=trust_by_context[context["id"]],
                sensitivity=sensitivity_by_context[context["id"]],
                catalog_sha=catalog_sha,
                bindings_sha=bindings_sha,
            )
            delivery, diagnostic, declared_path = _resolve_delivery(
                base,
                action=action,
                job=job,
                assignment=assignment,
                binding=binding,
                output_root=output_root,
                plugin_root=plugin_root,
                limits=bindings["limit_profiles"][binding["limit_profile"]],
                action_receipts=action_receipts,
            )
            if declared_path and declared_path in job.get("input_artifacts", []):
                matched_declared.add(declared_path)
            if "source_receipt" in delivery:
                delivered_bytes += delivery["source_receipt"]["byte_count"]
            deliveries.append(delivery)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
        unmatched = sorted(set(job.get("input_artifacts", [])) - matched_declared)
        if unmatched:
            raise ContextRoutingError(
                f"job {job['job_id']!r} has declared inputs without human catalog assignments: {', '.join(unmatched)}"
            )
        if delivered_bytes > limits["max_bytes"]:
            raise ContextRoutingError(f"agent {agent_id!r} exceeds its aggregate context-byte cap")

    old_action_ids = {action_id}
    plan["actions"] = [row for row in plan["actions"] if row["action_id"] not in old_action_ids] + [action_record]
    plan["deliveries"] = [row for row in plan["deliveries"] if row["action_id"] not in old_action_ids] + deliveries
    plan["diagnostics"] = [row for row in plan["diagnostics"] if row["action_id"] not in old_action_ids] + diagnostics
    plan["actions"].sort(key=lambda row: row["action_id"])
    plan["deliveries"].sort(key=lambda row: row["delivery_id"])
    plan["diagnostics"].sort(key=lambda row: (row["action_id"], row["job_id"], row["context_id"], row["code"]))
    plan["revision"] += 1
    _write_plan(output_root, plan)
    return plan


def bind_action_to_plan(action: dict[str, Any], plan: dict[str, Any], output_root: Path) -> dict[str, Any]:
    """Reference active plan entries without exposing the shared plan to agents."""
    basis_sha = _sha256(_canonical_json_bytes(_action_basis(action)))
    action_rows = [row for row in plan["actions"] if row["action_sha256"] == basis_sha]
    if len(action_rows) != 1:
        raise ContextRoutingError("effective context plan does not contain exactly one matching action")
    action_id = action_rows[0]["action_id"]
    active = [
        row for row in plan["deliveries"] if row["action_id"] == action_id and "plan-enforced" in row["disclosures"]
    ]
    if not active:
        return action

    bound = copy.deepcopy(action)
    by_job: dict[str, list[str]] = {}
    for row in active:
        by_job.setdefault(row["job_id"], []).append(row["delivery_id"])
    for job in bound["dispatch_jobs"]:
        delivery_ids = sorted(by_job.get(job["job_id"], []))
        if delivery_ids:
            job["context_delivery_ids"] = delivery_ids

    plan_path, receipt_path = _plan_paths(output_root.resolve())
    validated_plan = _validate_plan_receipt(plan_path, receipt_path)
    if validated_plan != plan:
        raise ContextRoutingError("effective context plan changed before action binding")
    receipt = _load_json(receipt_path)
    receipt_sha = _sha256(receipt_path.read_bytes())
    plan_artifact_receipt = {
        "schema_version": 1,
        "artifact_path": PLAN_NAME,
        "schema_id": PLAN_SCHEMA_ID,
        "sha256": receipt["sha256"],
        "record_count": receipt["record_count"],
        "validation_status": "valid",
    }
    receipts = [row for row in bound.get("artifact_receipts", []) if row.get("artifact_path") != PLAN_NAME]
    receipts.append(plan_artifact_receipt)
    bound["artifact_receipts"] = receipts
    bound["context_plan"] = {
        "artifact_path": PLAN_NAME,
        "receipt_path": PLAN_RECEIPT_NAME,
        "sha256": receipt["sha256"],
        "receipt_sha256": receipt_sha,
        "revision": plan["revision"],
        "action_id": action_id,
    }
    validate_action_plan_reference(bound, output_root)
    return bound


def validate_action_plan_reference(action: dict[str, Any], output_root: Path) -> None:
    """Fail closed when an action's active context-plan reference is stale."""
    reference = action.get("context_plan")
    if not isinstance(reference, dict):
        raise ContextRoutingError("active context action is missing its effective-plan reference")
    if reference.get("artifact_path") != PLAN_NAME or reference.get("receipt_path") != PLAN_RECEIPT_NAME:
        raise ContextRoutingError("effective-plan reference uses an unexpected path")
    plan_path, receipt_path = _plan_paths(output_root.resolve())
    plan = _validate_plan_receipt(plan_path, receipt_path)
    receipt = _load_json(receipt_path)
    if reference.get("sha256") != receipt["sha256"]:
        raise ContextRoutingError("effective-plan reference has a stale plan hash")
    if reference.get("receipt_sha256") != _sha256(receipt_path.read_bytes()):
        raise ContextRoutingError("effective-plan reference has a stale receipt hash")
    if reference.get("revision") != plan["revision"]:
        raise ContextRoutingError("effective-plan reference has a stale revision")

    basis_sha = _sha256(_canonical_json_bytes(_action_basis(action)))
    action_id = reference.get("action_id")
    matching_actions = [
        row for row in plan["actions"] if row["action_id"] == action_id and row["action_sha256"] == basis_sha
    ]
    if len(matching_actions) != 1:
        raise ContextRoutingError("effective-plan action binding is stale")

    deliveries = {row["delivery_id"]: row for row in plan["deliveries"] if row["action_id"] == action_id}
    expected_by_job: dict[str, set[str]] = {}
    for delivery_id, row in deliveries.items():
        if "plan-enforced" in row["disclosures"]:
            expected_by_job.setdefault(row["job_id"], set()).add(delivery_id)
    referenced: set[str] = set()
    for job in action.get("dispatch_jobs", []):
        actual = set(job.get("context_delivery_ids", []))
        expected = expected_by_job.get(job["job_id"], set())
        if actual != expected:
            raise ContextRoutingError(f"job {job['job_id']!r} has stale active context delivery references")
        for delivery_id in actual:
            row = deliveries.get(delivery_id)
            if row is None or row.get("component_id") != job.get("component_id"):
                raise ContextRoutingError(f"job {job['job_id']!r} references another job's context delivery")
        referenced.update(actual)
    if referenced != {delivery_id for values in expected_by_job.values() for delivery_id in values}:
        raise ContextRoutingError("active context deliveries are not fully referenced by the action")

    plan_receipts = [row for row in action.get("artifact_receipts", []) if row.get("artifact_path") == PLAN_NAME]
    if len(plan_receipts) != 1 or plan_receipts[0] != {
        "schema_version": 1,
        "artifact_path": PLAN_NAME,
        "schema_id": PLAN_SCHEMA_ID,
        "sha256": reference["sha256"],
        "record_count": receipt["record_count"],
        "validation_status": "valid",
    }:
        raise ContextRoutingError("action is missing the exact-byte effective-plan receipt")
    if any(PLAN_NAME in job.get("input_artifacts", []) for job in action.get("dispatch_jobs", [])):
        raise ContextRoutingError("the shared effective plan must not enter an agent input")


def inspect_plan(output_root: Path) -> str:
    """Return a content-free human summary grouped by category and agent."""
    plan_path, receipt_path = _plan_paths(output_root.resolve())
    plan = _validate_plan_receipt(plan_path, receipt_path)
    counts: dict[tuple[str, str, str], int] = {}
    for delivery in plan["deliveries"]:
        key = (delivery["category_name"], delivery["agent_name"], delivery["status"])
        counts[key] = counts.get(key, 0) + 1
    lines = [
        f"Context routing plan: {len(plan['actions'])} actions, {len(plan['deliveries'])} decisions",
    ]
    for (category, agent, status), count in sorted(counts.items()):
        lines.append(f"- {category} -> {agent}: {status} ({count})")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate the catalog, bindings, and agent assignments")
    inspect_parser = subparsers.add_parser("inspect", help="print a content-free effective-plan summary")
    inspect_parser.add_argument("output_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            catalog, bindings, _, _ = load_catalog_contracts()
            import orchestration_controller as controller

            validate_catalog_semantics(
                catalog,
                bindings,
                semantic_roles=controller.SEMANTIC_ROLE_REGISTRY,
                model_keys=controller.SEMANTIC_ROLE_MODEL_KEYS,
            )
            print(
                f"context-routing: schema- and semantic-valid catalog with {len(catalog['categories'])} categories, "
                f"{len(catalog['agents'])} agents, {len(catalog['contexts'])} contexts, "
                f"and {len(catalog['assignments'])} assignments; {len(bindings['contexts'])} runtime bindings"
            )
        else:
            print(inspect_plan(args.output_dir))
    except ContextRoutingError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
