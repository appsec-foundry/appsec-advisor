"""Contracts for the human context catalog and effective plan."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_permissions as permissions  # noqa: E402
import check_state  # noqa: E402
import context_routing as routing  # noqa: E402
import diagnostic_bundle  # noqa: E402
import orchestration_controller as controller  # noqa: E402
import package_internal_plugin as packager  # noqa: E402
import runtime_cleanup  # noqa: E402


def _contracts() -> tuple[dict, dict]:
    catalog, bindings, _, _ = routing.load_catalog_contracts()
    return catalog, bindings


def _semantic_validate(catalog: dict, bindings: dict) -> None:
    routing.validate_catalog_semantics(
        catalog,
        bindings,
        semantic_roles=controller.SEMANTIC_ROLE_REGISTRY,
        model_keys=controller.SEMANTIC_ROLE_MODEL_KEYS,
    )


def _context_action(output: Path, *, inputs: list[str] | None = None) -> dict:
    config = output / ".skill-config.json"
    if not config.exists():
        config.write_text('{"mode":"full","run_id":"test-run"}\n', encoding="utf-8")
    return {
        "schema_version": 1,
        "action": "dispatch_agent",
        "mode": "full",
        "stage": "stage1c",
        "instruction_file": str(controller.THIN_STAGE1_V2_RUNTIME),
        "config_path": str(config),
        "dispatch_values": {
            "output_dir": str(output),
            "run_id": "test-run",
            "context_resolver_model": "sonnet",
        },
        "semantic_role": "context_resolver",
        "dispatch_jobs": [
            {
                "schema_version": 1,
                "job_id": "phase1-context",
                "semantic_role": "context_resolver",
                "agent_type": "appsec-advisor:appsec-context-resolver",
                "model": "sonnet",
                "input_artifacts": [".skill-config.json"] if inputs is None else inputs,
                "output_artifacts": [".threat-modeling-context.md"],
                "unresolved_decision_keys": [],
            }
        ],
    }


def _resolve(action: dict, output: Path) -> dict:
    return routing.resolve_action(
        action,
        output,
        semantic_roles=controller.SEMANTIC_ROLE_REGISTRY,
        model_keys=controller.SEMANTIC_ROLE_MODEL_KEYS,
    )


def _generic_action(
    output: Path,
    role: str,
    job_id: str,
    inputs: list[str],
    *,
    component_id: str | None = None,
    candidate_id: str | None = None,
    receipted: bool = True,
) -> dict:
    job = {
        "schema_version": 1,
        "job_id": job_id,
        "semantic_role": role,
        "input_artifacts": inputs,
        "output_artifacts": [f".{job_id}.json"],
        "unresolved_decision_keys": ["decision"] if role in {"threat_merger", "post_stride_synthesizer"} else [],
    }
    if component_id:
        job["component_id"] = component_id
        job.update(
            attempt=1,
            analysis_depth="full",
            estimated_threat_count="moderate",
            file_count=3,
            lens_ids=[],
            max_turns=12,
            sampling_required=False,
        )
    if candidate_id:
        job["candidate_id"] = candidate_id
    action = {
        "schema_version": 1,
        "action": "dispatch_agent",
        "mode": "full",
        "stage": "stage1c",
        "dispatch_values": {"output_dir": str(output), "run_id": "test-run", "assessment_depth": "standard"},
        "dispatch_jobs": [job],
    }
    if receipted:
        _catalog, bindings = _contracts()
        receipts = []
        for binding in bindings["contexts"]:
            if binding.get("enforcement") != "active" or binding["source"]["kind"] != "output_artifact":
                continue
            artifact = binding["source"]["artifact_pattern"].format(
                component_id=component_id or "",
                candidate_id=candidate_id or "",
            )
            path = output / artifact
            if artifact not in inputs or not path.is_file():
                continue
            payload = path.read_bytes()
            receipts.append(
                {
                    "schema_version": 1,
                    "artifact_path": artifact,
                    "schema_id": binding["contract"],
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "record_count": 1,
                    "validation_status": "valid",
                }
            )
        if receipts:
            action["artifact_receipts"] = receipts
    return action


def test_catalog_and_bindings_validate_and_bind_to_the_runtime_registry():
    catalog, bindings = _contracts()
    _semantic_validate(catalog, bindings)
    assert {row["semantic_role"] for row in bindings["agents"] if row["runtime"] == "context_v2"} == set(
        controller.SEMANTIC_ROLE_REGISTRY
    )


def test_every_declared_limit_profile_field_is_enforced():
    _catalog, bindings = _contracts()
    enforced = set(routing._COUNT_LIMIT_KEYS.values())  # noqa: SLF001

    assert all(set(profile) == enforced for profile in bindings["limit_profiles"].values())


def test_human_validate_command_checks_schema_and_agent_assignments(capsys):
    assert routing._main(["validate"]) == 0
    assert "schema- and semantic-valid catalog" in capsys.readouterr().out


def test_human_catalog_contains_only_human_decisions():
    catalog, _ = _contracts()
    forbidden_keys = {
        "agent_type",
        "artifact_pattern",
        "contract",
        "enforcement",
        "limit_profile",
        "max_bytes",
        "max_items",
        "max_lines",
        "max_paths",
        "max_tokens",
        "model_setting",
        "plugin_path",
        "producer",
        "projector",
        "schema_id",
    }

    def walk(value):
        if isinstance(value, dict):
            assert not (set(value) & forbidden_keys)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(catalog)
    serialized = yaml.safe_dump(catalog, sort_keys=False)
    assert ".json" not in serialized and ".yaml" not in serialized
    assert "sha256" not in serialized.lower()


def test_human_categories_cover_the_stage1_security_story():
    catalog, _ = _contracts()
    categories = {row["id"] for row in catalog["categories"]}
    assert categories == {
        "target_and_run",
        "business_and_requirements",
        "repository_discovery",
        "architecture_and_data_flows",
        "actors_and_abuse_cases",
        "trust_boundaries",
        "security_controls_and_evidence",
        "threat_analysis",
        "verification_and_risk",
        "prior_runs_and_identity",
    }
    contexts = {row["id"]: row for row in catalog["contexts"]}
    assert contexts["business.project_context"]["category"] == "business_and_requirements"
    assert contexts["abuse_cases.matches"]["category"] == "actors_and_abuse_cases"
    assert contexts["trust_boundaries.assessment"]["category"] == "trust_boundaries"
    assert contexts["threats.merged"]["category"] == "threat_analysis"
    assert all(any(context["category"] == category for context in catalog["contexts"]) for category in categories)


def test_every_context_has_a_visible_assignment_or_explicit_forbidden_policy():
    catalog, _ = _contracts()
    assigned = {assignment["context"] for assignment in catalog["assignments"]}
    assert {context["id"] for context in catalog["contexts"]} <= assigned
    prior = next(assignment for assignment in catalog["assignments"] if assignment["context"] == "prior_run.findings")
    assert prior["delivery"] == "forbidden"
    assert prior["agents"] == ["stride_analyzer"]


def test_every_assignment_is_readable_and_points_to_named_agents_and_context():
    catalog, _ = _contracts()
    agents = {row["id"]: row for row in catalog["agents"]}
    contexts = {row["id"]: row for row in catalog["contexts"]}
    pairs: set[tuple[str, str]] = set()
    for assignment in catalog["assignments"]:
        assert len(assignment["reason"].split()) >= 6
        assert assignment["context"] in contexts
        for agent_id in assignment["agents"]:
            assert agent_id in agents
            assert agents[agent_id]["name"] and agents[agent_id]["purpose"]
            assert (agent_id, assignment["context"]) not in pairs
            pairs.add((agent_id, assignment["context"]))
    assert ("abuse_case_verifier", "abuse_cases.matches") in pairs
    assert ("trust_boundary_analyst", "trust_boundaries.assessment") in pairs
    assert ("stride_analyzer", "controls.component_evidence") in pairs


def test_runtime_parameters_are_isolated_in_plugin_owned_bindings():
    catalog, bindings = _contracts()
    catalog_text = (ROOT / "data" / "context-routing-catalog.yaml").read_text(encoding="utf-8")
    binding_text = json.dumps(bindings)
    for term in ("max_bytes", "max_tokens", "artifact_pattern", "projector", "model_setting"):
        assert term not in catalog_text
        assert term in binding_text
    assert all("limits" not in assignment for assignment in catalog["assignments"])
    assert "availability" not in catalog_text
    assert "component_types" not in catalog_text


def test_assignment_targets_match_the_threat_modeling_unit():
    catalog, _ = _contracts()
    by_id = {assignment["id"]: assignment for assignment in catalog["assignments"]}
    assert by_id["stride-component-evidence"]["applies_to"] == "current_component"
    assert by_id["abuse-case-candidates"]["applies_to"] == "current_candidate"
    assert by_id["stride-dispatch-plan"]["applies_to"] == "current_component"
    assert by_id["stride-related-repositories"]["applies_to"] == "current_component"


def test_semantics_reject_unknown_agent_and_contradictory_assignment():
    catalog, bindings = _contracts()
    unknown = copy.deepcopy(catalog)
    unknown["assignments"][0]["agents"] = ["unknown_agent"]
    with pytest.raises(routing.ContextRoutingError, match="unknown agent"):
        _semantic_validate(unknown, bindings)

    duplicate = copy.deepcopy(catalog)
    duplicate["assignments"].append(copy.deepcopy(duplicate["assignments"][0]))
    duplicate["assignments"][-1]["id"] = "duplicate-run-config"
    with pytest.raises(routing.ContextRoutingError, match="duplicate or contradictory"):
        _semantic_validate(duplicate, bindings)


def test_semantics_reject_invalid_importance_and_dependency_cycle():
    catalog, bindings = _contracts()
    weak_required = copy.deepcopy(catalog)
    weak_required["assignments"][0]["importance"] = "supporting"
    with pytest.raises(routing.ContextRoutingError, match="must be essential"):
        _semantic_validate(weak_required, bindings)

    cyclic = copy.deepcopy(bindings)
    by_id = {row["id"]: row for row in cyclic["contexts"]}
    by_id["run.configuration"]["depends_on"] = ["run.assessment_depth"]
    by_id["run.assessment_depth"]["depends_on"] = ["run.configuration"]
    with pytest.raises(routing.ContextRoutingError, match="dependency cycle"):
        _semantic_validate(catalog, cyclic)


def test_semantics_reject_target_that_broadens_component_or_candidate_context():
    catalog, bindings = _contracts()
    broad_component = copy.deepcopy(catalog)
    assignment = next(row for row in broad_component["assignments"] if row["id"] == "stride-component-evidence")
    assignment["applies_to"] = "whole_run"
    with pytest.raises(routing.ContextRoutingError, match="must target 'current_component'"):
        _semantic_validate(broad_component, bindings)

    broad_candidate = copy.deepcopy(catalog)
    assignment = next(row for row in broad_candidate["assignments"] if row["id"] == "abuse-case-candidates")
    assignment["applies_to"] = "whole_run"
    with pytest.raises(routing.ContextRoutingError, match="must target 'current_candidate'"):
        _semantic_validate(broad_candidate, bindings)


@pytest.mark.parametrize("unsafe", ["/tmp/input.json", "../input.json", "https://example.test/input", "a/*/input"])
def test_semantics_reject_unsafe_artifact_bindings(unsafe):
    catalog, bindings = _contracts()
    changed = copy.deepcopy(bindings)
    changed["contexts"][0]["source"]["artifact_pattern"] = unsafe
    with pytest.raises(routing.ContextRoutingError, match="unsafe|literal"):
        _semantic_validate(catalog, changed)


def test_semantics_reject_missing_schema_referenced_by_active_route():
    catalog, bindings = _contracts()
    changed = copy.deepcopy(bindings)
    route = next(row for row in changed["contexts"] if row["id"] == "architecture.route_projection")
    route["contract"] = "schemas/missing-active-route.schema.json#v1"

    with pytest.raises(routing.ContextRoutingError, match="plugin context path is missing"):
        _semantic_validate(catalog, changed)


def test_static_and_resolved_actor_routes_use_distinct_contracts():
    _catalog, bindings = _contracts()
    by_id = {row["id"]: row for row in bindings["contexts"]}

    assert by_id["actors.static"]["contract"] == "schemas/actors-merged-static.schema.yaml#v1", (
        "RA-1: the static actor boundary needs its own artifact contract"
    )
    assert by_id["actors.resolved"]["contract"] == "schemas/actors-resolved.schema.yaml#v1", (
        "RA-1: the resolved actor boundary must retain its authoritative contract"
    )


def test_semantics_reject_plugin_symlink_escape(tmp_path):
    catalog, bindings = _contracts()
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("checks: []\n", encoding="utf-8")
    (plugin / "escape.yaml").symlink_to(outside)
    changed = copy.deepcopy(bindings)
    binding = next(row for row in changed["contexts"] if row["id"] == "discovery.config_checks")
    binding["source"]["plugin_path"] = "escape.yaml"
    with pytest.raises(routing.ContextRoutingError, match="escapes the plugin"):
        routing.validate_catalog_semantics(
            catalog,
            changed,
            semantic_roles=controller.SEMANTIC_ROLE_REGISTRY,
            model_keys=controller.SEMANTIC_ROLE_MODEL_KEYS,
            plugin_root=plugin,
        )


def test_shadow_plan_explains_delivery_omission_and_legacy_read(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    plan = _resolve(_context_action(output), output)
    by_context = {row["context_id"]: row for row in plan["deliveries"]}
    assert by_context["run.configuration"]["status"] == "delivered"
    assert by_context["run.configuration"]["scope"] == "whole_run"
    assert by_context["run.configuration"]["applies_to"] == "whole_run"
    assert (
        by_context["run.configuration"]["source_receipt"]["sha256"]
        == hashlib.sha256((output / ".skill-config.json").read_bytes()).hexdigest()
    )
    assert by_context["requirements.security"]["status"] == "omitted_optional"
    assert by_context["business.context_sources"]["status"] == "legacy_unreceipted"
    assert by_context["run.configuration"]["agent_name"] == "Project context resolver"
    assert by_context["run.configuration"]["category_name"] == "Target and run"
    assert by_context["run.configuration"]["reason"]
    assert (output / routing.PLAN_RECEIPT_NAME).is_file()


def test_effective_plan_rejects_semantic_action_replay_but_accepts_new_attempt_identity(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    action = _context_action(output)
    _resolve(action, output)

    with pytest.raises(routing.ContextRoutingError, match="already issued"):
        routing.assert_action_not_replayed(action, output)
    with pytest.raises(routing.ContextRoutingError, match="already resolved"):
        _resolve(action, output)

    retry = copy.deepcopy(action)
    retry["dispatch_jobs"][0]["job_id"] = "phase1-context:attempt-2"
    routing.assert_action_not_replayed(retry, output)
    plan = _resolve(retry, output)
    assert len(plan["actions"]) == 2


def test_active_declared_context_rejects_unreceipted_existing_bytes(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    path = output / ".recon-patterns.json"
    path.write_text("{}\n", encoding="utf-8")
    action = _generic_action(
        output,
        "recon_scanner",
        "phase2-recon",
        [".recon-patterns.json"],
        receipted=False,
    )

    with pytest.raises(routing.ContextRoutingError, match="lacks a validated action receipt"):
        _resolve(action, output)


def test_structured_line_profiles_count_serialization_not_semantic_windows():
    _catalog, bindings = _contracts()
    sample = {
        "t_id": "T-001",
        "title": "title",
        "scenario": "scenario",
        "risk": "High",
        "source": "stride",
        "evidence_summary": "summary",
        "evidence": {"file": "src/api.ts", "line": 10},
        "source_sha256": "a" * 64,
        "source_window": [{"line": index, "text": "source"} for index in range(1, 12)],
    }
    payload = (json.dumps({"samples": [sample] * 64}, indent=2) + "\n").encode()
    counts = routing._counts(payload, record_count=64)  # noqa: SLF001
    profile = bindings["limit_profiles"]["evidence_sample"]

    assert counts["line_count"] > 2_816
    assert counts["byte_count"] <= profile["max_bytes"]
    routing._enforce_limits("verification.evidence_sample", counts, profile)  # noqa: SLF001

    mitigation = {
        "t_id": "T-001",
        "mitigation_title": None,
        "effort": None,
        "steps": ["step"] * 20,
        "verification": None,
        "reference": None,
    }
    mitigation_payload = (json.dumps({"mitigations": [mitigation] * 512}, indent=2) + "\n").encode()
    mitigation_counts = routing._counts(mitigation_payload, record_count=512)  # noqa: SLF001
    mitigation_profile = bindings["limit_profiles"]["post_stride_projection"]

    assert mitigation_counts["line_count"] > 10_000
    assert mitigation_counts["byte_count"] <= mitigation_profile["max_bytes"]
    routing._enforce_limits(  # noqa: SLF001
        "threats.proposed_mitigations_projection",
        mitigation_counts,
        mitigation_profile,
    )


def test_every_context_v2_agent_declared_input_has_one_human_assignment(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    jobs = [
        ("context_resolver", "phase1-context", [".skill-config.json"], None),
        ("recon_scanner", "phase2-recon", [".skill-config.json"], None),
        ("config_scanner", "phase2-config", [".skill-config.json"], None),
        (
            "actor_discoverer",
            "phase2-actors",
            [
                ".actors-merged-static.json",
                ".dispatch-context/architecture/recon-summary-context.json",
                ".recon-signals.json",
            ],
            None,
        ),
        (
            "architecture_analyst",
            "phase3-architecture",
            [
                ".dispatch-context/architecture/recon-summary-context.json",
                ".dispatch-context/architecture/route-context.json",
                ".actors-resolved.json",
            ],
            None,
        ),
        ("trust_boundary_analyst", "phase7-boundary", [".trust-boundary-assessment-input.json"], None),
        (
            "control_analyst",
            "phase8-controls",
            [
                ".components.json",
                ".trust-boundaries.json",
                ".architecture-coverage.json",
                ".threat-modeling-context.md",
            ],
            None,
        ),
        (
            "stride_analyzer",
            "phase9-stride-api",
            [
                ".dispatch-context/api/context-plan.json",
                ".dispatch-context/api/evidence-bundle.json",
                ".dispatch-context/api/repository-roots.json",
                ".taxonomy-slices/api/threat-category-taxonomy.yaml",
            ],
            "api",
        ),
        ("threat_merger", "phase9-merge", [".merge-context/candidates.json"], None),
        (
            "evidence_verifier",
            "phase10-evidence",
            [".dispatch-context/post-stride/evidence-sample.json"],
            None,
        ),
        ("triage_validator", "phase10-triage", [".threats-merged.json", ".triage-flags.json"], None),
        (
            "post_stride_synthesizer",
            "phase10-synthesis",
            [
                ".dispatch-context/post-stride/generated-threats.json",
                ".dispatch-context/post-stride/proposed-mitigations.json",
            ],
            None,
        ),
    ]
    for _, _, inputs, _ in jobs:
        for relative in inputs:
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n", encoding="utf-8")
    for role, job_id, inputs, component_id in jobs:
        plan = _resolve(_generic_action(output, role, job_id, inputs, component_id=component_id), output)
        assert any(row["agent_id"] == role for row in plan["deliveries"])
        if role == "stride_analyzer":
            stride = {row["context_id"]: row for row in plan["deliveries"] if row["agent_id"] == role}
            assert stride["controls.component_evidence"]["scope"] == "one_component"
            assert stride["controls.component_evidence"]["applies_to"] == "current_component"
            assert stride["business.component_context"]["scope"] == "one_component"
            assert stride["business.component_context"]["applies_to"] == "current_component"
            assert stride["architecture.component_context"]["scope"] == "one_component"
            assert stride["architecture.component_context"]["applies_to"] == "current_component"
            assert stride["threats.dispatch_plan"]["scope"] == "one_component"
            assert stride["threats.dispatch_plan"]["applies_to"] == "current_component"
            assert stride["threats.related_repositories"]["scope"] == "one_component"
            assert stride["threats.related_repositories"]["applies_to"] == "current_component"
    assert len(plan["actions"]) == len(jobs)


def test_forbidden_shared_context_cannot_enter_focused_agent_inputs(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    inputs = [
        ".dispatch-context/api/context-plan.json",
        ".dispatch-context/api/evidence-bundle.json",
        ".taxonomy-slices/api/threat-category-taxonomy.yaml",
        ".recon-summary.md",
    ]
    for relative in inputs:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    action = _generic_action(output, "stride_analyzer", "phase9-stride-api", inputs, component_id="api")
    with pytest.raises(routing.ContextRoutingError, match="forbidden context"):
        _resolve(action, output)


def test_candidate_scoped_abuse_context_resolves_only_for_its_job(tmp_path):
    output = tmp_path / "out"
    relative = ".dispatch-context/abuse-cases/AC-T-001.json"
    path = output / relative
    path.parent.mkdir(parents=True)
    path.write_text("{}\n", encoding="utf-8")

    plan = _resolve(
        _generic_action(
            output,
            "abuse_case_verifier",
            "phase10c-AC-T-001",
            [relative],
            candidate_id="AC-T-001",
        ),
        output,
    )

    delivery = next(row for row in plan["deliveries"] if row["context_id"] == "abuse_cases.matches")
    assert delivery["candidate_id"] == "AC-T-001"
    assert delivery["scope"] == "one_candidate"


def test_shadow_plan_rejects_unassigned_declared_input(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "extra.json").write_text("{}\n", encoding="utf-8")
    action = _context_action(output, inputs=[".skill-config.json", "extra.json"])
    with pytest.raises(routing.ContextRoutingError, match="without human catalog assignments"):
        _resolve(action, output)


def test_shadow_plan_rejects_missing_required_input(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    action = _context_action(output, inputs=[])
    with pytest.raises(routing.ContextRoutingError, match="required context"):
        _resolve(action, output)


def test_shadow_plan_rejects_output_symlink_escape(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (output / ".skill-config.json").symlink_to(outside)
    with pytest.raises(routing.ContextRoutingError, match="escapes the output directory"):
        _resolve(_context_action(output), output)


def test_shadow_plan_enforces_internal_size_limit(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps({"payload": "x" * 1_048_576}), encoding="utf-8")
    with pytest.raises(routing.ContextRoutingError, match="exceeds max_bytes"):
        _resolve(_context_action(output), output)


def test_shadow_plan_rejects_stale_action_receipt(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    action = _context_action(output)
    action["artifact_receipts"] = [
        {
            "schema_version": 1,
            "artifact_path": ".skill-config.json",
            "schema_id": "contract:resolved-run-config-v1",
            "sha256": "0" * 64,
            "record_count": 1,
            "validation_status": "valid",
        }
    ]
    with pytest.raises(routing.ContextRoutingError, match="stale"):
        _resolve(action, output)


def test_exact_byte_plan_receipt_detects_mutation(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    _resolve(_context_action(output), output)
    plan_path = output / routing.PLAN_NAME
    plan_path.write_text(plan_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(routing.ContextRoutingError, match="changed after"):
        routing.inspect_plan(output)


def test_active_stride_deliveries_bind_to_one_receipted_plan_without_agent_exposure(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    inputs = [
        ".dispatch-context/api/context-plan.json",
        ".dispatch-context/api/evidence-bundle.json",
        ".dispatch-context/api/repository-roots.json",
        ".taxonomy-slices/api/threat-category-taxonomy.yaml",
    ]
    for relative in inputs:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    action = _generic_action(output, "stride_analyzer", "phase9-stride-api", inputs, component_id="api")
    action["dispatch_values"]["stride_profile"] = {"stride_profile_label": "full"}
    plan = _resolve(action, output)

    active = {row["context_id"] for row in plan["deliveries"] if "plan-enforced" in row["disclosures"]}
    assert active == {
        "architecture.component_context",
        "business.component_context",
        "actors.component_context",
        "controls.component_evidence",
        "controls.component_context",
        "prior_run.component_findings",
        "requirements.component_context",
        "threats.dispatch_plan",
        "threats.component_taxonomy",
        "threats.known_threats",
        "threats.related_repositories",
        "threats.analysis_lenses",
        "threats.analysis_settings",
        "trust_boundaries.component_context",
    }
    bound = routing.bind_action_to_plan(action, plan, output)
    routing.validate_action_plan_reference(bound, output)
    assert len(bound["dispatch_jobs"][0]["context_delivery_ids"]) == 14
    assert routing.PLAN_NAME not in bound["dispatch_jobs"][0]["input_artifacts"]
    assert bound["context_plan"]["artifact_path"] == routing.PLAN_NAME

    receipt_path = output / routing.PLAN_RECEIPT_NAME
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(routing.ContextRoutingError, match="stale receipt hash"):
        routing.validate_action_plan_reference(bound, output)


def test_component_business_context_is_delivered_only_when_selected(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    required_inputs = [
        ".dispatch-context/api/context-plan.json",
        ".dispatch-context/api/evidence-bundle.json",
        ".taxonomy-slices/api/threat-category-taxonomy.yaml",
    ]
    business_path = ".dispatch-context/api/business-context.json"
    for relative in [*required_inputs, business_path]:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")

    omitted_action = _generic_action(
        output,
        "stride_analyzer",
        "phase9-stride-api-without-business",
        required_inputs,
        component_id="api",
    )
    omitted_plan = _resolve(omitted_action, output)
    omitted = next(
        row
        for row in omitted_plan["deliveries"]
        if row["job_id"] == "phase9-stride-api-without-business" and row["context_id"] == "business.component_context"
    )
    assert omitted["status"] == "omitted_optional"
    assert business_path not in omitted_action["dispatch_jobs"][0]["input_artifacts"]

    selected_action = _generic_action(
        output,
        "stride_analyzer",
        "phase9-stride-api-with-business",
        [*required_inputs, business_path],
        component_id="api",
    )
    selected_plan = _resolve(selected_action, output)
    selected = next(
        row
        for row in selected_plan["deliveries"]
        if row["job_id"] == "phase9-stride-api-with-business" and row["context_id"] == "business.component_context"
    )
    assert selected["status"] == "delivered"
    assert selected["source_receipt"]["artifact_path"] == business_path


def test_component_architecture_context_is_delivered_only_when_selected(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    required_inputs = [
        ".dispatch-context/api/context-plan.json",
        ".dispatch-context/api/evidence-bundle.json",
        ".taxonomy-slices/api/threat-category-taxonomy.yaml",
    ]
    architecture_path = ".dispatch-context/api/architecture-context.json"
    for relative in [*required_inputs, architecture_path]:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")

    omitted_action = _generic_action(
        output,
        "stride_analyzer",
        "phase9-stride-api-without-architecture",
        required_inputs,
        component_id="api",
    )
    omitted_plan = _resolve(omitted_action, output)
    omitted = next(
        row
        for row in omitted_plan["deliveries"]
        if row["job_id"] == "phase9-stride-api-without-architecture"
        and row["context_id"] == "architecture.component_context"
    )
    assert omitted["status"] == "omitted_optional"
    assert architecture_path not in omitted_action["dispatch_jobs"][0]["input_artifacts"]

    selected_action = _generic_action(
        output,
        "stride_analyzer",
        "phase9-stride-api-with-architecture",
        [*required_inputs, architecture_path],
        component_id="api",
    )
    selected_plan = _resolve(selected_action, output)
    selected = next(
        row
        for row in selected_plan["deliveries"]
        if row["job_id"] == "phase9-stride-api-with-architecture"
        and row["context_id"] == "architecture.component_context"
    )
    assert selected["status"] == "delivered"
    assert selected["source_receipt"]["artifact_path"] == architecture_path


def test_prior_plan_rejects_changed_catalog_hash(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    action = _context_action(output)
    _resolve(action, output)
    original = routing.load_catalog_contracts()
    monkeypatch.setattr(routing, "load_catalog_contracts", lambda: (*original[:2], "f" * 64, original[3]))
    with pytest.raises(routing.ContextRoutingError, match="stale catalog"):
        _resolve(action, output)


def test_every_context_v2_role_can_be_dispatched(tmp_path):
    """No catalog role may be structurally undispatchable.

    The dispatch hook denies any context-v2 Agent call whose prompt carries no
    ACTION_ID, and the runtime takes that value from `context_plan.action_id`.
    A role that cannot be bound therefore cannot run at all — which is how
    trust_boundary_analyst and threat_merger blocked a full assessment. This
    asserts the property for every role, so a future catalog edit that leaves a
    role without an active context fails here instead of mid-run.
    """
    catalog, bindings = _contracts()
    binding_by_id = {b["id"]: b for b in bindings["contexts"]}
    component_id, candidate_id = "web-api", "AC-T-001"
    checked = 0
    for agent in bindings["agents"]:
        role = agent["semantic_role"]
        if role not in controller.SEMANTIC_ROLE_REGISTRY:
            continue
        # Declare exactly the inputs this role's catalog assignments require,
        # so the run reaches binding rather than failing input validation.
        contract_by_artifact: dict[str, str] = {}
        for assignment in catalog["assignments"]:
            if agent["id"] not in assignment["agents"] or assignment["delivery"] == "forbidden":
                continue
            binding = binding_by_id[assignment["context"]]
            if binding["delivery"] != "declared" or binding["source"]["kind"] != "output_artifact":
                continue
            artifact = routing._render_artifact(
                binding["source"]["artifact_pattern"], component_id, candidate_id
            )
            contract_by_artifact[artifact] = binding["contract"]
        inputs = sorted(contract_by_artifact)
        output = tmp_path / f"out-{role}"
        output.mkdir()
        action = _context_action(output, inputs=inputs)
        action["semantic_role"] = role
        action["dispatch_values"][controller.SEMANTIC_ROLE_MODEL_KEYS[role]] = "sonnet"
        job = action["dispatch_jobs"][0]
        job["semantic_role"] = role
        job["agent_type"] = f"appsec-advisor:{agent['agent_type']}"
        job["component_id"] = component_id
        job["candidate_id"] = candidate_id
        receipts = []
        for relative in job["input_artifacts"]:
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = b"{}\n"
            path.write_bytes(payload)
            receipts.append(
                {
                    "schema_version": 1,
                    "artifact_path": relative,
                    "schema_id": contract_by_artifact[relative],
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "record_count": 1,
                    "validation_status": "valid",
                }
            )
        action["artifact_receipts"] = receipts
        plan = _resolve(action, output)
        bound = routing.bind_action_to_plan(action, plan, output)
        assert bound.get("context_plan", {}).get("action_id"), f"{role} cannot receive an ACTION_ID"
        routing.validate_action_plan_reference(bound, output)
        checked += 1
    assert checked == len(controller.SEMANTIC_ROLE_REGISTRY)


def test_controller_emit_binds_identity_on_a_shadow_only_action(tmp_path, capsys):
    """A role with no active context still gets its ACTION_ID.

    `context_resolver` has only shadow-only contexts, as the catalog migration
    is incremental by design. Binding used to be skipped entirely for such a
    role, so the emitted action carried no `action_id` — while the dispatch
    hook requires ACTION_ID from every context-v2 role and the runtime prompt
    reads `context_plan.action_id`. That made four roles undispatchable.
    Identity is now always bound; only enforcement stays conditional.
    """
    output = tmp_path / "out"
    output.mkdir()
    action = _context_action(output)
    code = controller._emit(action)
    emitted = json.loads(capsys.readouterr().out)
    assert code == 0
    assert emitted["context_plan"]["action_id"]
    assert emitted["context_plan"]["artifact_path"] == routing.PLAN_NAME
    routing.validate_action_plan_reference(emitted, output)
    # Shadow stays observable where it belongs: no enforced delivery is
    # referenced, and the run log still reports the mode as shadow.
    assert "context_delivery_ids" not in emitted["dispatch_jobs"][0]
    assert "CONTEXT_ROUTING_SHADOW" in (output / ".agent-run.log").read_text(encoding="utf-8")
    # The shared plan is an audit artifact: it may be referenced and receipted,
    # but must never become an agent input.
    assert routing.PLAN_NAME not in emitted["dispatch_jobs"][0]["input_artifacts"]
    assert (output / routing.PLAN_NAME).is_file()


def test_inspection_is_human_readable_and_content_free(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text('{"mode":"full","run_id":"secret-project-name"}\n', encoding="utf-8")
    _resolve(_context_action(output), output)
    summary = routing.inspect_plan(output)
    assert "Business context and requirements -> Project context resolver" in summary
    assert "secret-project-name" not in summary
    assert ".skill-config.json" not in summary


def test_fresh_run_reset_removes_only_plan_pair(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    _resolve(_context_action(output), output)
    keep = output / "keep.txt"
    keep.write_text("keep\n", encoding="utf-8")
    routing.reset_plan(output)
    assert not (output / routing.PLAN_NAME).exists()
    assert not (output / routing.PLAN_RECEIPT_NAME).exists()
    assert keep.is_file()


def test_plan_lifecycle_is_audit_preserved_but_fresh_run_rebuilt():
    for name in (routing.PLAN_NAME, routing.PLAN_RECEIPT_NAME):
        assert name not in runtime_cleanup.ALWAYS_FILES
        assert name not in check_state._CLEANUP_TARGETS
        assert name in controller._FULL_INTERMEDIATE_NAMES
        assert name in controller._REBUILD_NAMES


def test_plan_uses_existing_permissions_and_is_not_copied_into_diagnostics():
    entries = permissions.load_required(ROOT / "data" / "required-permissions.yaml")
    rules = [entry["entry"] for entry in entries]
    assert any(
        permissions._rule_covers(rule, "Read(${PLUGIN_ROOT}/data/context-routing-catalog.yaml)") for rule in rules
    )
    assert any(permissions._rule_covers(rule, "Write(${OUTPUT_DIR}/.context-routing-plan.json)") for rule in rules)
    assert routing.PLAN_NAME not in diagnostic_bundle.LOG_NAMES
    assert routing.PLAN_RECEIPT_NAME not in diagnostic_bundle.LOG_NAMES
    reasons = " ".join(entry["reason"] for entry in entries)
    assert "context catalog" in reasons and "context-routing plan" in reasons


def test_catalog_runtime_bindings_and_schemas_are_packaged(tmp_path):
    build = tmp_path / "build"
    packager.copy_source(ROOT, build)
    for relative in (
        "data/context-routing-catalog.yaml",
        "data/context-routing-bindings.json",
        "schemas/context-routing-catalog.schema.json",
        "schemas/context-routing-bindings.schema.json",
        "schemas/context-effective-plan.schema.json",
        "schemas/context-effective-plan-receipt.schema.json",
        "schemas/stride-component-context-plan.schema.json",
        "scripts/context_routing.py",
    ):
        assert (build / relative).is_file()
