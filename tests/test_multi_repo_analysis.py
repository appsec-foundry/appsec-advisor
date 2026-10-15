"""Semantic jobs retain qualified evidence and cannot invent peer authority."""

import copy
import hashlib
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts import multi_repo_analysis as stage
from runtime.assessment_host import ExchangeError, Rejection
from runtime.multi_repo_scope import AssessmentScope, RepositoryView

FP = "sha256:" + "a" * 64


def sources(tmp_path, path="app.py"):
    repos = tuple(
        RepositoryView(
            f"repo-{i:016x}", tmp_path / f"repo{i}", "b" * 40, "c" * 64, {path: b"result = request.args['input']\n"}
        )
        for i in (1, 2)
    )
    scope = AssessmentScope(repos, tmp_path / "output")
    components = [
        dict(
            id=f"component-{i}",
            name="Service",
            tier="application",
            repository_ids=[r.repository_id],
            paths=[dict(repository_id=r.repository_id, path=path, sha256=hashlib.sha256(r.files[path]).hexdigest())],
        )
        for i, r in enumerate(repos, 1)
    ]
    evidence = [
        dict(repository_id=r.repository_id, file=path, line=1, sha256=components[i]["paths"][0]["sha256"])
        for i, r in enumerate(repos)
    ]
    ranges = [
        dict(repository_id=e["repository_id"], path=e["file"], sha256=e["sha256"], start_line=1, end_line=1)
        for e in evidence
    ]
    identity = dict(
        schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], component_inventory_fingerprint=FP
    )
    return scope, components, evidence, ranges, identity


def stride(component, evidence, identity):
    finding = dict(
        local_id="issue-1",
        title="Unvalidated input reaches the request handler",
        stride="Tampering",
        scenario="An attacker submits malformed input to the request handler.",
        likelihood="Medium",
        impact="Medium",
        risk="Medium",
        evidence=evidence,
        evidence_tier="insecure-practice",
        threat_category_id="TH-01",
        cwe="CWE-20",
        remediation=dict(
            effort="Low",
            steps=["Validate the input against the accepted data type.", "Reject requests that fail validation."],
            verification="Submit malformed input and assert that the endpoint rejects it.",
        ),
    )
    coverage = [
        dict(
            category=category,
            disposition="finding" if category == "Tampering" else "no-evidence",
            finding_ids=["issue-1"] if category == "Tampering" else [],
            reason="Retrieved source does not establish another finding.",
        )
        for category in stage.STRIDE_CATEGORIES
    ]
    return dict(
        **identity,
        component_id=component["id"],
        component_name=component["name"],
        analyzed_at="2026-01-01T00:00:00Z",
        partial=False,
        skipped_categories=[],
        coverage=coverage,
        threats=[finding],
    )


def test_valid_stride_and_independent_verification_preserve_sources(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    original = copy.deepcopy(artifact)
    stage.validate_stride(
        scope, components[0], components, dict(component_inventory_fingerprint=FP, data_flows=[]), artifact, ranges[:1]
    )
    assert artifact == original
    review = dict(
        **identity,
        decisions=[
            dict(
                local_id="issue-1",
                verdict="verified",
                reason="The independently read anchor implements the reported practice.",
                evidence=[evidence[0]],
            )
        ],
    )
    stage.validate_evidence_review(
        scope, artifact["threats"], FP, review, ranges[:1], stage.source_selection(components)
    )


@pytest.mark.parametrize(
    "kind", ["valid", "missing", "duplicate", "unread", "unresolved", "foreign", "unknown-finding"]
)
def test_source_surface_coverage_cannot_be_satisfied_by_category_labels(tmp_path, kind):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    architecture = {
        "data_flows": {"data_flows": []},
        "route_inventories": {
            evidence[0]["repository_id"]: {"routes": [{"handler_file": "app.py", "handler_line": 1}]},
        },
    }
    targets = stage.analysis_targets(scope, components[0], architecture, [])
    assert len(targets) == 1 and targets[0]["kinds"] == ["route"]
    artifact = stride(components[0], evidence[0], identity)
    row = dict(
        target_id=targets[0]["local_id"],
        disposition="examined",
        reason="The handler consumes the retrieved input.",
        finding_ids=["issue-1"],
        evidence=[evidence[0]],
    )
    artifact["surface_coverage"] = [row]
    if kind == "missing":
        artifact.pop("surface_coverage")
    elif kind == "duplicate":
        artifact["surface_coverage"].append(copy.deepcopy(row))
    elif kind == "unread":
        ranges = ranges[1:]
    elif kind == "unresolved":
        row["disposition"] = "unresolved"
    elif kind == "foreign":
        row["evidence"] = [evidence[1]]
    elif kind == "unknown-finding":
        row["finding_ids"] = ["not-a-finding"]
    if kind in ("valid", "unresolved"):
        # MR-11: a target the job read may stay unresolved; the run names it.
        stage.validate_surface_coverage(artifact, ranges, targets)
        assert bool(stage.unresolved_targets(artifact, targets)) is (kind == "unresolved")
        if kind == "unresolved":
            # The file and the model's reason say what is open; the anchor line of a
            # file-level target is arbitrary, and one repository needs no qualifier.
            anchor = targets[0]["evidence"]
            assert stage.unresolved_targets(artifact, targets, qualified=False) == [
                f"{anchor['file']}: The handler consumes the retrieved input."
            ]
            assert stage.unresolved_targets(artifact, targets) == [
                f"{anchor['repository_id']}/{anchor['file']}: The handler consumes the retrieved input."
            ]
    else:
        with pytest.raises(ValueError):
            stage.validate_surface_coverage(artifact, ranges, targets)


@pytest.mark.parametrize("kind", ["other-line", "extra-anchors", "foreign", "unread"])
def test_a_read_target_needs_no_exact_anchor_copy_but_an_unread_one_still_fails(tmp_path, kind):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    architecture = {
        "data_flows": {"data_flows": []},
        "route_inventories": {
            evidence[0]["repository_id"]: {"routes": [{"handler_file": "app.py", "handler_line": 1}]},
        },
    }
    targets = stage.analysis_targets(scope, components[0], architecture, [])
    artifact = stride(components[0], evidence[0], identity)
    cited = {**evidence[0], "line": evidence[0]["line"] + 1, "sha256": "f" * 64}
    rows = {
        "other-line": [cited],
        "extra-anchors": [cited] * 4,
        "foreign": [evidence[1]],
        "unread": [cited],
    }[kind]
    artifact["surface_coverage"] = [
        dict(
            target_id=targets[0]["local_id"],
            disposition="examined",
            reason="The handler consumes the retrieved input.",
            finding_ids=["issue-1"],
            evidence=copy.deepcopy(rows),
        )
    ]
    if kind == "unread":
        ranges = ranges[1:]
    normalized = stage.surface_evidence_normalizer(targets)(copy.deepcopy(artifact))
    assert stage.surface_evidence_normalizer(targets)(copy.deepcopy(normalized)) == normalized
    if kind in ("other-line", "extra-anchors"):
        stage.validate_surface_coverage(normalized, ranges, targets)
        assert len(normalized["surface_coverage"][0]["evidence"]) <= 4
    else:
        with pytest.raises(ValueError):
            stage.validate_surface_coverage(normalized, ranges, targets)


def test_a_component_keeps_every_finding_its_bounded_jobs_returned():
    """MR-12: the combined document allows each job's limit, so no paid finding fails the merge."""
    per_job = stage.contract("multi-repo-stride.schema.json")["properties"]["threats"]["maxItems"]
    assert stage.component_stride_contract(3)["properties"]["threats"]["maxItems"] == 3 * per_job
    finding_ids = stage.component_stride_contract(3)["properties"]["coverage"]["items"]["properties"]["finding_ids"]
    assert finding_ids["maxItems"] == 3 * per_job
    assert "maxItems" not in stage.component_stride_contract(None)["properties"]["threats"]
    # A single job keeps its own limit.
    assert stage.component_stride_contract(1)["properties"]["threats"]["maxItems"] == per_job


@pytest.mark.parametrize("path", ["policy/check.py", "domain/permit.kt"])
def test_files_without_scanner_signals_still_need_investigation(tmp_path, path):
    from dataclasses import replace

    scope, components, evidence, _, _ = sources(tmp_path)
    repo = scope.repositories[0]
    repo = replace(repo, files={**repo.files, path: b"custom_permission_check()\n", "empty.txt": b""})
    scope = replace(scope, repositories=(repo, scope.repositories[1]))
    component = components[0]
    component["paths"] += [dict(repository_id=repo.repository_id, path=p) for p in (path, "empty.txt")]
    architecture = {"data_flows": {"data_flows": [{"evidence": [evidence[0]]}]}}
    targets = stage.analysis_targets(scope, component, architecture, [])
    assert {t["evidence"]["file"] for t in targets} == {"app.py", path}
    assert next(t for t in targets if t["evidence"]["file"] == path)["kinds"] == ["component-source"]


@pytest.mark.parametrize(
    "path,source,expected",
    [
        # A license header precedes the first statement of a file without a lead.
        # Each file carries a security signal (MR-13), so it is a target at all.
        (
            "models/order.ts",
            b"/*\n * Copyright (c) Example\n */\n\nimport { Model } from 'orm'\nclass Order { query() {} }\n",
            5,
        ),
        (
            "store/ledger.py",
            b"#!/usr/bin/env python3\n# SPDX-License-Identifier: MIT\n\nrows = load()\nexec(rows)\n",
            4,
        ),
        # A file that starts with code keeps its first line.
        ("lib/basket.ts", b"export const total = 0\n// end\nexport const token = ''\n", 1),
    ],
)
def test_file_targets_cite_the_first_line_the_evidence_rule_accepts(tmp_path, path, source, expected):
    from validators.validate_fragment import _cited_line_problem

    scope, component = _owned_sources(
        tmp_path, {path: source, "notes.ts": b"// only a comment\n\n"}, [path, "notes.ts"]
    )
    targets = stage.analysis_targets(scope, component, {"data_flows": {"data_flows": []}}, [])
    # A comment-only file offers no line to cite and therefore no target.
    assert [(t["evidence"]["file"], t["evidence"]["line"]) for t in targets] == [(path, expected)]
    assert _cited_line_problem(source.decode().splitlines()[expected - 1], allow_imports=True) is None


@pytest.mark.parametrize("lead,expected", [(2, 3), (4, 3), (3, 3)])
def test_a_lead_on_a_comment_moves_to_the_nearest_following_code_line(tmp_path, lead, expected):
    source = b"import express from 'express'\n// handler\nrouter.get('/order', show)\n\n"
    scope, component = _owned_sources(tmp_path, {"routes/order.ts": source}, ["routes/order.ts"])
    architecture = {
        "data_flows": {"data_flows": []},
        "route_inventories": {
            scope.repositories[0].repository_id: {"routes": [{"handler_file": "routes/order.ts", "handler_line": lead}]}
        },
    }
    targets = stage.analysis_targets(scope, component, architecture, [])
    # A trailing blank lead has no following code line and falls back to the previous one.
    assert [(t["evidence"]["line"], t["kinds"]) for t in targets] == [(expected, ["route"])]


@pytest.mark.parametrize("path", ["api/submit.py", "web/ingest.ts"])
def test_surface_targets_include_egress_without_a_modelled_flow(tmp_path, path):
    scope, components, evidence, ranges, identity = sources(tmp_path, path)
    # The projection uses an arbitrary existing source anchor, not a filename heuristic.
    anchor = evidence[0]
    architecture = {
        "data_flows": {"data_flows": []},
        "egress_inventories": {
            anchor["repository_id"]: [{"evidence": [{"file": path, "line": 1}]}],
            evidence[1]["repository_id"]: [{"evidence": [{"file": path, "line": 1}]}],
        },
    }
    targets = stage.analysis_targets(scope, components[0], architecture, [])
    assert len(targets) == 1 and targets[0]["evidence"] == anchor
    assert targets[0]["kinds"] == ["outbound-call"]


def test_surface_batches_preserve_all_targets_and_reserve_followup_reads(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    targets = [dict(local_id=f"surface-{i:016x}", evidence={**evidence[0], "line": 400 * i + 1}) for i in range(15)]
    batches = stage.evidence_batches(targets, max_windows=6, max_findings=64, window_lines=400)
    assert [len(batch) for batch in batches] == [6, 6, 3]
    assert {t["local_id"] for b in batches for t in b} == {t["local_id"] for t in targets}


def test_stride_parts_keep_every_finding_and_remap_category_references(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    parts = [stride(components[0], evidence[0], identity) for _ in range(2)]
    combined = stage.combine_stride_parts(parts)
    assert len(combined["threats"]) == 2
    ids = {f["local_id"] for f in combined["threats"]}
    assert len(ids) == 2
    assert set(next(c for c in combined["coverage"] if c["category"] == "Tampering")["finding_ids"]) == ids
    assert parts[0]["threats"][0]["local_id"] == "issue-1"


def test_selected_lenses_use_existing_selector_and_plugin_policy(tmp_path):
    scope, components, _, _, _ = sources(tmp_path)
    selected, policy = stage.analysis_lenses(
        scope, {**components[0], "id": "client", "name": "Portal", "tier": "client"}
    )
    assert selected == ["spa"] and (stage.ROOT / "agents/shared/spa-threats.md").read_text() == policy
    selected, policy = stage.analysis_lenses(
        scope, {**components[0], "id": "worker", "name": "Worker", "lens_ids": ["../../foreign"]}
    )
    assert selected == [] and policy == ""


def _owned_sources(tmp_path, files, owned):
    repo = RepositoryView("repo-" + "1" * 16, tmp_path / "repo", "b" * 40, "c" * 64, files)
    scope = AssessmentScope((repo,), tmp_path / "output")
    component = dict(
        id="component-1",
        name="Service",
        tier="application",
        repository_ids=[repo.repository_id],
        paths=[dict(repository_id=repo.repository_id, path=path) for path in owned],
    )
    return scope, component


@pytest.mark.parametrize(
    "path,source",
    [
        ("service/reply.py", b"from anthropic import Anthropic\nclient = Anthropic()\n"),
        (
            "features/helper.ts",
            b"import { createOpenAICompatible } from '@ai-sdk/openai-compatible'\nconst provider = createOpenAICompatible({name: 'assistant'})\n",
        ),
    ],
)
def test_llm_surfaces_require_separate_mechanism_decisions_without_a_finding_quota(tmp_path, path, source):
    scope, component = _owned_sources(tmp_path, {path: source}, [path])
    targets = stage.analysis_targets(scope, component, {"data_flows": {"data_flows": []}}, [])
    questions = [t for t in targets if t.get("review_question")]
    assert {t["review_check"] for t in questions} == set(stage.LLM_REVIEW_QUESTIONS)
    assert len(questions) == 6
    assert len({t["local_id"] for t in targets}) == len(targets)
    # Shared anchors reuse a read window, not six independent jobs.
    assert len(stage.evidence_batches(targets, max_windows=6, max_findings=64, window_lines=400)) == 1
    ranges = [{**t["evidence"], "path": path, "start_line": 1, "end_line": 2} for t in targets]
    artifact = {
        "threats": [],
        "surface_coverage": [
            {
                "target_id": t["local_id"],
                "disposition": "not-applicable",
                "finding_ids": [],
                "reason": "The supplied source constructs a client but exposes no model action.",
                "evidence": [t["evidence"]],
            }
            for t in targets
        ],
    }
    stage.validate_surface_coverage(artifact, ranges, targets)
    row = next(r for r in artifact["surface_coverage"] if r["target_id"] == questions[0]["local_id"])
    row.update(disposition="examined", finding_ids=["issue-1"])
    artifact["threats"] = [{"local_id": "issue-1"}]
    normalized = stage.surface_evidence_normalizer(targets)(copy.deepcopy(artifact))
    assert (
        next(r for r in normalized["surface_coverage"] if r["target_id"] == row["target_id"])["reason"] == row["reason"]
    )
    row.pop("reason")
    with pytest.raises(Rejection, match="incomplete"):
        stage.validate_surface_coverage(artifact, ranges, targets)
    row.update(disposition="unresolved", finding_ids=[], reason="The tool implementation is unavailable.")
    stage.validate_surface_coverage(artifact, ranges, targets)
    assert stage.unresolved_targets(artifact, targets, qualified=False) == [
        f"{path} (client-context): The tool implementation is unavailable."
    ]


@pytest.mark.parametrize("mode", ["unused", "foreign", "test"])
def test_llm_review_questions_do_not_promote_unused_or_unowned_integrations(tmp_path, mode):
    source = b"from anthropic import Anthropic\n" + (b"" if mode == "unused" else b"client = Anthropic()\n")
    path = "tests/test_chat.py" if mode == "test" else "chat.py"
    scope, component = _owned_sources(
        tmp_path, {path: source, "app.py": b"value = 1\n"}, ["app.py"] if mode == "foreign" else [path]
    )
    targets = stage.analysis_targets(scope, component, {"data_flows": {"data_flows": []}}, [])
    assert not [t for t in targets if t.get("review_question")]


def test_controller_keeps_llm_decisions_in_the_existing_stride_exchange(tmp_path):
    from orchestrator import orchestration_controller as controller
    from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import Host, checkout

    roots = [tmp_path / name for name in ("service", "peer")]
    for root in roots:
        checkout(root)
    path = roots[0] / "app.py"
    path.write_text(path.read_text() + "from anthropic import Anthropic\nclient = Anthropic()\n")
    scope = admit([str(root) for root in roots], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(2, 0.05, 60, 120),
        host.factory,
        lambda: False,
        lambda: None,
    )
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda _: None)
    documents, _, _ = controller._assessment_stride(scope, jobs, architecture, [], [], progress=lambda _: None)
    calls = [ctx for role, ctx in host.calls if role == "stride_analyzer"]
    assert len(calls) == 2  # one preloaded exchange per component, including the ordinary peer
    questions = [t for ctx in calls for t in ctx["investigation_targets"] if t.get("review_question")]
    assert {t["review_check"] for t in questions} == set(stage.LLM_REVIEW_QUESTIONS)
    assert any("Answer each review_question independently" in system for system in host.systems)
    decisions = {row["target_id"]: row for document in documents for row in document["surface_coverage"]}
    assert all(decisions[t["local_id"]].get("reason") for t in questions)


@pytest.mark.parametrize(
    "path,source",
    [
        ("routes/chat.ts", b"import { createOpenAICompatible } from '@ai-sdk/openai-compatible'\n"),
        ("svc/assistant/reply.py", b"from anthropic import Anthropic\nclient = Anthropic()\n"),
    ],
)
def test_owned_llm_source_selects_the_llm_lens_for_a_generic_component(tmp_path, path, source):
    # Twenty-five strong hits elsewhere precede the owned file; a repository-wide
    # excerpt cap must not decide whether this component receives the lens.
    noise = {f"aaa/other{i}.py": b"import openai\n" for i in range(25)}
    scope, component = _owned_sources(
        tmp_path, {**noise, path: source, "server.ts": b"app.listen(3000)\n"}, [path, "server.ts"]
    )
    selected, policy = stage.analysis_lenses(scope, component)
    assert "llm" in selected
    assert (stage.ROOT / "agents/shared/owasp-llm-top10.md").read_text() in policy


@pytest.mark.parametrize(
    "files,owned",
    [
        # Prompt vocabulary alone is weak and does not prove a model call.
        ({"routes/verify.ts": b"const systemPrompt = loadSystemPrompt()\n"}, ["routes/verify.ts"]),
        # A provider named only in configuration is not application source.
        ({"config/default.yml": b"llm: openai\n", "app.ts": b"app.listen(3000)\n"}, ["config/default.yml", "app.ts"]),
        # Another component's model call does not select this component's lens.
        ({"chat/call.ts": b"import OpenAI from 'openai'\n", "shop/cart.ts": b"cart.add(item)\n"}, ["shop/cart.ts"]),
    ],
)
def test_llm_lens_requires_a_strong_signal_in_owned_source(tmp_path, files, owned):
    scope, component = _owned_sources(tmp_path, files, owned)
    assert stage.known_llm_patterns(scope, component) == ""
    assert "llm" not in stage.analysis_lenses(scope, component)[0]
    assert stage.model_integration_leads(scope, [component]) == []


@pytest.mark.parametrize("path,line", [("app.py", 1), ("svc/models/index.ts", 7)])
def test_unretrieved_evidence_rejection_names_each_citation(tmp_path, path, line):
    from runtime.assessment_host import Rejection

    files = {path: b"\n".join(b"row = %d" % i for i in range(1, 10)) + b"\n", "other.py": b"pass\n"}
    scope, component = _owned_sources(tmp_path, files, [path, "other.py"])
    rid = scope.repositories[0].repository_id
    digest = {p: hashlib.sha256(files[p]).hexdigest() for p in files}
    cited = dict(repository_id=rid, file=path, line=line, sha256=digest[path])
    read = dict(repository_id=rid, file="other.py", line=1, sha256=digest["other.py"])
    artifact = {"evidence": [cited, read]}
    ranges = [dict(repository_id=rid, path="other.py", sha256=digest["other.py"], start_line=1, end_line=1)]
    allowed = stage.source_selection([component])
    with pytest.raises(Rejection) as raised:
        stage.validate_retrieved_sources(scope, artifact, ranges, allowed)
    assert raised.value.errors == [f"{rid}/{path}:{line} was not read; read it or remove the claim"]
    # Once the cited window is delivered, the same claims pass.
    ranges.append(dict(repository_id=rid, path=path, sha256=digest[path], start_line=1, end_line=9))
    stage.validate_retrieved_sources(scope, artifact, ranges, allowed)


@pytest.mark.parametrize(
    "source,expected",
    [
        # The provider is named only in the import; the call uses the imported binding.
        (
            b"import { streamText } from 'ai'\nimport { createOpenAICompatible } from '@ai-sdk/openai-compatible'\n"
            b"\nconst provider = createOpenAICompatible({ baseURL: url })\n",
            [4],
        ),
        (b"from anthropic import Anthropic\n\n# client\nclient = Anthropic(api_key=key)\n", [4]),
        # An import that is never called offers nothing the evidence rule would accept.
        (b"import OpenAI from 'openai'\nexport const unused = 1\n", []),
    ],
)
def test_model_integration_leads_cite_only_lines_the_evidence_rule_accepts(tmp_path, source, expected):
    from validators.validate_fragment import _cited_line_problem

    scope, component = _owned_sources(tmp_path, {"svc/model.ts": source}, ["svc/model.ts"])
    leads = stage.model_integration_leads(scope, [component])
    lines = [row["line"] for lead in leads for row in lead["evidence"]]
    assert lines == expected
    text = source.decode().splitlines()
    assert all(_cited_line_problem(text[line - 1], allow_imports=False) is None for line in lines)


def test_model_integration_gap_closes_only_with_a_flow_to_an_inference_service(tmp_path):
    source = b"// assistant\nimport OpenAI from 'openai'\nconst client = new OpenAI()\n"
    scope, component = _owned_sources(tmp_path, {"assist/reply.ts": source}, ["assist/reply.ts"])
    leads = stage.model_integration_leads(scope, [component])
    assert leads == [{"component_id": "component-1", "evidence": [{"file": "assist/reply.ts", "line": 3}]}]
    inference = {"id": "ext-model", "service_roles": [{"role": "llm-inference", "evidence": []}]}
    other = {"id": "ext-rpc", "service_roles": [{"role": "blockchain-rpc", "evidence": []}]}
    flow = {"from": "component-1", "to": "ext-model"}
    assert stage.model_integration_gaps(leads, {"external_entities": [other], "data_flows": []}) == ["component-1"]
    unrelated = {"external_entities": [inference, other], "data_flows": [{"from": "component-1", "to": "ext-rpc"}]}
    assert stage.model_integration_gaps(leads, unrelated) == ["component-1"]
    assert stage.model_integration_gaps(leads, {"external_entities": [inference], "data_flows": [flow]}) == []


@pytest.mark.parametrize(
    "flow",
    [
        {"from": "component-1", "to": "external", "to_entity": "ext-model"},
        {"from": "external", "from_entity": "ext-model", "to": "component-1"},
    ],
    ids=["outbound", "inbound"],
)
def test_a_flow_naming_its_inference_entity_closes_the_gap(tmp_path, flow):
    """A local architecture's external flow names its entity in to_entity/from_entity (Juice Shop chatbot)."""
    source = (
        b"import { createOpenAICompatible } from '@ai-sdk/openai-compatible'\nconst p = createOpenAICompatible({})\n"
    )
    scope, component = _owned_sources(tmp_path, {"routes/chat.ts": source}, ["routes/chat.ts"])
    leads = stage.model_integration_leads(scope, [component])
    inference = {"id": "ext-model", "service_roles": [{"role": "llm-inference", "evidence": []}]}
    rpc = {"id": "ext-rpc", "service_roles": [{"role": "blockchain-rpc", "evidence": []}]}
    assert leads and stage.model_integration_gaps(leads, {"external_entities": [inference], "data_flows": [flow]}) == []
    # An entity flow to another service still leaves the gap open.
    other = {**flow, **{key: "ext-rpc" for key in ("to_entity", "from_entity") if key in flow}}
    assert stage.model_integration_gaps(leads, {"external_entities": [inference, rpc], "data_flows": [other]}) == [
        "component-1"
    ]


@pytest.mark.parametrize(
    "kind",
    [
        "owner",
        "hash",
        "unknown-field",
        "coverage",
        "identity",
        "missing-source",
        "unretrieved",
        "requirements",
        "partial",
    ],
)
def test_stride_rejects_forged_or_incomplete_work(tmp_path, kind):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    if kind == "owner":
        artifact["threats"][0]["evidence"] = evidence[1]
    elif kind == "hash":
        artifact["threats"][0]["evidence"]["sha256"] = "0" * 64
    elif kind == "unknown-field":
        artifact["execute"] = "command"
    elif kind == "coverage":
        artifact["coverage"][1]["finding_ids"] = []
    elif kind == "identity":
        artifact["component_id"] = components[1]["id"]
    elif kind == "requirements":
        artifact["threats"][0]["violated_requirements"] = ["INVENTED-01"]
    elif kind == "partial":
        artifact["partial"] = True
    else:
        ranges = []
        if kind == "missing-source":
            artifact["threats"] = []
            for row in artifact["coverage"]:
                row.update(disposition="no-evidence", finding_ids=[])
    with pytest.raises(ValueError):
        stage.validate_stride(
            scope, components[0], components, dict(component_inventory_fingerprint=FP, data_flows=[]), artifact, ranges
        )


@pytest.mark.parametrize(
    ("cited", "allowed", "accepted"),
    [
        (["SEC-AUTH-1"], {"SEC-AUTH-1", "SEC-LOG-2"}, True),
        (["SEC-AUTH-1", "SEC-AUTH-9"], {"SEC-AUTH-1"}, False),
        (["SEC-AUTH-1"], frozenset(), False),
    ],
)
def test_stride_cites_only_requirements_of_its_supplied_catalog(tmp_path, cited, allowed, accepted):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    artifact["threats"][0]["violated_requirements"] = cited
    original = copy.deepcopy(artifact)

    def run():
        stage.validate_stride(
            scope,
            components[0],
            components,
            dict(component_inventory_fingerprint=FP, data_flows=[]),
            artifact,
            ranges[:1],
            allowed_requirement_ids=allowed,
        )

    if accepted:
        run()
        assert artifact == original
    else:
        with pytest.raises(ExchangeError, match="requirements absent"):
            run()


def test_peer_neighborhood_does_not_expand_through_a_shared_broker(tmp_path):
    _, components, _, _, _ = sources(tmp_path)
    broker = dict(id="broker", paths=[], repository_ids=[])
    another = dict(id="another-consumer", paths=[], repository_ids=[])
    flows = dict(
        data_flows=[
            {"from": components[0]["id"], "to": "broker"},
            {"from": "broker", "to": components[1]["id"]},
            {"from": "broker", "to": "another-consumer"},
        ]
    )
    neighborhood = stage.component_neighborhood(
        dict(components=components + [broker, another]), flows, components[0]["id"]
    )
    assert {c["id"] for c in neighborhood} == {components[0]["id"], "broker"}


@pytest.mark.parametrize("connected", [False, True])
def test_cross_repository_trace_requires_a_directional_reviewed_flow(tmp_path, connected):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[1], evidence[1], identity)
    finding = artifact["threats"][0]
    finding.update(
        cwe="CWE-89",
        evidence_tier="confirmed-exploitable",
        mechanism_trace=dict(
            input=evidence[0],
            sink=evidence[1],
            connection="The sender's request reaches the receiver's query without parameterization.",
            control=dict(
                status="absent-at-sink",
                location=evidence[1],
                explanation="The query at the cited sink executes the unvalidated request value.",
            ),
        ),
    )
    flows = dict(
        component_inventory_fingerprint=FP,
        data_flows=[dict(**{"from": components[0]["id"], "to": components[1]["id"]})] if connected else [],
    )
    if connected:
        stage.validate_stride(scope, components[1], components, flows, artifact, ranges)
    else:
        with pytest.raises(ExchangeError, match="directional"):
            stage.validate_stride(scope, components[1], components, flows, artifact, ranges)


def test_comment_cannot_substitute_for_implementation_evidence(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    views = list(scope.repositories)
    views[0] = RepositoryView(
        views[0].repository_id, views[0].root, "b" * 40, "c" * 64, {"app.py": b"# result = request.args['input']\n"}
    )
    scope = AssessmentScope(tuple(views), scope.output)
    evidence[0]["sha256"] = hashlib.sha256(views[0].files["app.py"]).hexdigest()
    ranges[0]["sha256"] = evidence[0]["sha256"]
    identity["source_scope_sha256"] = scope.inventory()["scope_sha256"]
    artifact = stride(components[0], evidence[0], identity)
    with pytest.raises(ExchangeError, match="executable"):
        stage.validate_stride(
            scope,
            components[0],
            components,
            dict(component_inventory_fingerprint=FP, data_flows=[]),
            artifact,
            ranges[:1],
        )


@pytest.mark.parametrize(
    ("risk", "steps", "accepted"),
    [("Critical", None, False), ("Critical", 2, True), ("High", None, True)],
)
def test_critical_finding_without_attack_steps_is_corrected(tmp_path, risk, steps, accepted):
    """MR-22: a Critical rating needs a traceable path; the rejection names the finding for a correction."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    finding = artifact["threats"][0]
    finding["risk"] = risk
    finding["attack_steps"] = (
        None if steps is None else [f"Step {n}: the attacker sends a crafted request." for n in range(steps)]
    )
    check = (
        lambda: stage.validate_stride(  # noqa: E731
            scope,
            components[0],
            components,
            dict(component_inventory_fingerprint=FP, data_flows=[]),
            artifact,
            ranges[:1],
        )
    )
    if accepted:
        check()
        return
    with pytest.raises(Rejection) as raised:
        check()
    assert "attack_steps" in str(raised.value) and finding["local_id"] in str(raised.value.errors)


def _commented(tmp_path, line, cwe):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    views = list(scope.repositories)
    views[0] = RepositoryView(views[0].repository_id, views[0].root, "b" * 40, "c" * 64, {"app.py": line.encode()})
    scope = AssessmentScope(tuple(views), scope.output)
    evidence[0]["sha256"] = hashlib.sha256(views[0].files["app.py"]).hexdigest()
    ranges[0]["sha256"] = evidence[0]["sha256"]
    identity["source_scope_sha256"] = scope.inventory()["scope_sha256"]
    artifact = stride(components[0], evidence[0], identity)
    artifact["threats"][0]["cwe"] = cwe
    flows = dict(component_inventory_fingerprint=FP, data_flows=[])
    return lambda: stage.validate_stride(scope, components[0], components, flows, artifact, ranges[:1])


@pytest.mark.parametrize(
    "line",
    [
        "  // app.put('/api/records/:id', guard.requireLogin()) // disabled for the demo\n",
        "# router.add_route('DELETE', '/records', require_admin(handler))\n",
    ],
)
def test_absence_finding_may_cite_a_commented_out_guard(tmp_path, line):
    """MR-20: the disabled guard statement is the evidence that the control is missing."""
    _commented(tmp_path, line, "CWE-306")()


@pytest.mark.parametrize(
    ("line", "cwe"),
    [
        ("# TODO: protect this route with requireLogin() later\n", "CWE-306"),
        ("# see require_admin() for the check\n", "CWE-862"),
        ("  // app.put('/api/records/:id', guard.requireLogin())\n", "CWE-89"),
    ],
)
def test_prose_comment_stays_rejected(tmp_path, line, cwe):
    with pytest.raises(ExchangeError, match="executable"):
        _commented(tmp_path, line, cwe)()


@pytest.mark.parametrize("kind", ["stale", "missing", "duplicate", "borrowed-anchor"])
def test_evidence_review_cannot_forge_completion(tmp_path, kind):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    review = dict(
        **identity,
        decisions=[
            dict(
                local_id="issue-1",
                verdict="verified",
                reason="Independent source review supports the finding.",
                evidence=[evidence[0]],
            )
        ],
    )
    if kind == "stale":
        review["component_inventory_fingerprint"] = "sha256:" + "0" * 64
    elif kind == "missing":
        review["decisions"] = []
    elif kind == "duplicate":
        review["decisions"] *= 2
    else:
        review["decisions"][0]["evidence"] = [evidence[1]]
    with pytest.raises(ExchangeError) as raised:
        stage.validate_evidence_review(
            scope, artifact["threats"], FP, review, ranges, stage.source_selection(components)
        )
    # The correction turn must learn which decision to fix, not only that one is off.
    expected = {"missing": "missing: issue-1", "duplicate": "repeated: issue-1"}.get(kind)
    if expected:
        assert expected in str(raised.value)


@pytest.mark.parametrize("repositories", [1, 2])
def test_a_sole_repository_must_name_a_protected_asset(tmp_path, repositories):
    combined, components, evidence, ranges, _identity = sources(tmp_path)
    scope = AssessmentScope(combined.repositories[:repositories], tmp_path / "output")
    rid = components[0]["repository_ids"][0]
    inventory = dict(components=components[:repositories], source_scope_sha256=scope.inventory()["scope_sha256"])
    identity = dict(
        schema_version=2, source_scope_sha256=inventory["source_scope_sha256"], component_inventory_fingerprint=FP
    )
    empty = dict(**identity, repository_id=rid, data_flows=[], external_entities=[], assets=[])
    arguments = (scope, rid, inventory, dict(component_inventory_fingerprint=FP))
    if repositories == 1:
        with pytest.raises(ExchangeError, match="no protected asset"):
            stage.validate_local_architecture(*arguments, empty, ranges)
    else:
        stage.validate_local_architecture(*arguments, empty, ranges)
    asset = dict(
        id="asset-orders",
        name="Order records",
        classification="Confidential",
        description="Customer orders the service stores.",
        component_refs=[dict(component_id=components[0]["id"], relation="processed", evidence=[evidence[0]])],
    )
    stage.validate_local_architecture(*arguments, {**empty, "assets": [asset]}, ranges)


def test_evidence_batches_keep_every_anchor_readable_within_one_review():
    def finding(local_id, file, line=10, kind=None):
        evidence = {"repository_id": "r", "file": file, "line": line, **({"kind": kind} if kind else {})}
        return {"local_id": local_id, "evidence": evidence}

    findings = [finding(f"f{i}", f"wf/{i % 13}.yml") for i in range(29)] + [
        finding("same-window", "wf/0.yml", 20),
        finding("absence", "wf/1.yml", None, "absence"),
    ]
    batches = stage.evidence_batches(findings, max_windows=8, max_findings=15, window_lines=400)
    assert sorted(f["local_id"] for batch in batches for f in batch) == sorted(f["local_id"] for f in findings)
    for batch in batches:
        assert len(batch) <= 15
        assert len({(f["evidence"]["file"], (f["evidence"]["line"] or 0) // 400) for f in batch}) <= 8
    # Findings that one slice can show stay in one review.
    assert len(stage.evidence_batches(findings[:3], max_windows=8, max_findings=15, window_lines=400)) == 1


def test_local_architecture_cannot_promote_a_peer_without_connection_review(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = dict(
        **identity, repository_id=evidence[0]["repository_id"], data_flows=[], external_entities=[], assets=[]
    )
    stage.validate_local_architecture(
        scope,
        evidence[0]["repository_id"],
        dict(components=components, source_scope_sha256=identity["source_scope_sha256"]),
        dict(component_inventory_fingerprint=FP),
        artifact,
        [],
    )
    artifact["assets"] = [
        dict(
            id="asset-records",
            name="Records",
            classification="Internal",
            description="Application records.",
            component_refs=[dict(component_id=components[1]["id"], relation="processed", evidence=[evidence[0]])],
        )
    ]
    with pytest.raises(ExchangeError, match="outside"):
        stage.validate_local_architecture(
            scope,
            evidence[0]["repository_id"],
            dict(components=components, source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )


def _role_architecture(evidence, identity, schemes, *, via_client, access=None):
    """One legitimate role whose request path carries the given authentication schemes."""
    role = dict(id="ext-member", name="Member", kind="legitimate-role", description="Uses the service.")
    role["evidence"] = [evidence]
    if access:
        role["access"] = access

    def flow(number, source, target, scheme=None, **extra):
        row = dict(
            id=f"df-{number:03d}",
            label="Request",
            protocol="HTTPS",
            data_classification="internal",
            direction="unidirectional",
            evidence=[evidence],
            provenance="architecture",
            **{"from": source, "to": target},
            **extra,
        )
        if scheme:
            row["authentication"] = dict(scheme=scheme, scope="Request handler check.", evidence=[evidence])
        return row

    if via_client:
        flows = [flow(1, "external", "component-ui", from_entity="ext-member", interaction=True)]
        flows += [flow(n, "component-ui", "component-api", s) for n, s in enumerate(schemes, 2)]
    else:
        flows = [flow(n, "external", "component-api", s, from_entity="ext-member") for n, s in enumerate(schemes, 1)]
    return dict(
        **identity,
        repository_id=evidence["repository_id"],
        data_flows=flows,
        external_entities=[role],
        assets=[],
    )


@pytest.mark.parametrize("via_client", [False, True])
@pytest.mark.parametrize(
    ("schemes", "access"),
    [(["none", "bearer"], None), (["none", "bearer"], "internet-user"), (["none", "none"], None)],
)
def test_local_architecture_leaves_a_mixed_role_path_to_classification(tmp_path, via_client, schemes, access):
    """A mixed request path is no analyst error; the controller splits the role after the handoff."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    rid = evidence[0]["repository_id"]
    local = [dict(components[0], id="component-api")]
    if via_client:
        local.append(dict(components[0], id="component-ui", name="Browser client", tier="client"))
    artifact = _role_architecture(evidence[0], identity, schemes, via_client=via_client, access=access)
    call = (
        lambda: stage.validate_local_architecture(  # noqa: E731
            scope,
            rid,
            dict(components=local + components[1:], source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )
    )
    call()


def test_controls_cannot_borrow_evidence_from_another_owner(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = dict(
        **identity,
        security_controls=[
            dict(
                domain="Input Validation",
                control="Request Validation",
                effectiveness="Partial",
                assessment="Only part of the request is validated.",
                component_ids=[components[0]["id"]],
                evidence=[evidence[0]],
            )
        ],
    )
    stage.validate_controls(scope, components, FP, artifact, ranges)
    artifact["security_controls"][0]["evidence"] = [evidence[1]]
    with pytest.raises(ExchangeError, match="owned"):
        stage.validate_controls(scope, components, FP, artifact, ranges)


@pytest.mark.parametrize(
    "path,source,line,problem",
    [
        ("app.py", b"token = issue()\n\nstore(token)\n", 2, "blank line"),
        ("web/signin.ts", b"const t = auth()\n// keep the token\nlocalStorage.setItem('t', t)\n", 2, "comment"),
    ],
    ids=["blank-line", "comment"],
)
def test_a_control_citing_a_blank_line_is_corrected_in_its_own_job(tmp_path, path, source, line, problem):
    """MR-15: a control is held to STRIDE's executable-line check, so later jobs never inherit its bad anchor."""
    from runtime.assessment_host import Rejection

    repo = RepositoryView("repo-" + "1" * 16, tmp_path / "repo", "b" * 40, "c" * 64, {path: source})
    scope = AssessmentScope((repo,), tmp_path / "output")
    digest = hashlib.sha256(source).hexdigest()
    component = dict(
        id="component-1",
        name="Client",
        tier="application",
        repository_ids=[repo.repository_id],
        paths=[dict(repository_id=repo.repository_id, path=path, sha256=digest)],
    )
    identity = dict(
        schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], component_inventory_fingerprint=FP
    )
    ranges = [dict(repository_id=repo.repository_id, path=path, sha256=digest, start_line=1, end_line=3)]
    evidence = dict(repository_id=repo.repository_id, file=path, line=line, sha256=digest)
    control = dict(
        domain="Authentication",
        control="Client-side token storage",
        effectiveness="Weak",
        assessment="The token is readable by any script.",
        component_ids=[component["id"]],
        evidence=[evidence],
    )
    artifact = dict(**identity, security_controls=[control])
    with pytest.raises(Rejection, match="Control evidence") as raised:
        stage.validate_controls(scope, [component], FP, artifact, ranges)
    assert problem in str(raised.value)
    # Named for an anchor-only correction (MR-2), not a regenerated result.
    assert [row["line"] for row, _ in raised.value.anchors] == [line]
    control["evidence"] = [dict(evidence, line=3)]
    stage.validate_controls(scope, [component], FP, artifact, ranges)


@pytest.mark.parametrize(
    ("domain", "control"),
    [
        ("Trust-boundary enforcement", "postMessage origin validation"),
        ("Perimeter hygiene", "Open redirect and navigation validation"),
    ],
)
def test_a_control_no_report_section_takes_is_corrected_in_its_job(tmp_path, domain, control):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    row = dict(
        domain=domain,
        control=control,
        effectiveness="Missing",
        assessment="No check was found.",
        component_ids=[components[0]["id"]],
        evidence=[evidence[0]],
    )
    artifact = dict(**identity, security_controls=[row])
    with pytest.raises(ExchangeError, match="Browser and Cross-Origin Controls") as caught:
        stage.validate_controls(scope, components, FP, artifact, ranges)
    assert "Security Control Overview" not in str(caught.value)
    # The everyday domains the report normalizes keep passing.
    artifact["security_controls"] = [dict(row, domain="Authentication", control="Password hashing")]
    stage.validate_controls(scope, components, FP, artifact, ranges)


def test_stage_contracts_are_closed_and_local_refs_do_not_fetch_network():
    for name in stage.CONTRACTS[:4]:
        schema = stage.contract(name)
        assert schema["additionalProperties"] is False
        Draft202012Validator.check_schema(schema)
    with pytest.raises(ExchangeError, match="Unknown"):
        stage.contract("https://example.invalid/remote.json")


@pytest.mark.parametrize(("kind", "accepted"), [("absence", True), (None, False)])
def test_an_absence_is_verified_by_any_retrieved_range_of_its_anchor_file(tmp_path, kind, accepted):
    data = b"COPY . .\nRUN install\nCMD start\n"
    repo, other = (
        RepositoryView(f"repo-{i:016x}", tmp_path / f"repo{i}", "b" * 40, "c" * 64, {"Dockerfile": data})
        for i in (1, 2)
    )
    scope = AssessmentScope((repo, other), tmp_path / "output")
    sha = hashlib.sha256(data).hexdigest()
    anchor = dict(repository_id=repo.repository_id, file="Dockerfile", line=1, sha256=sha)
    if kind:
        anchor.update(kind=kind, searched_files=["Dockerfile"], searched_file_count=1)
    identity = dict(
        schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], component_inventory_fingerprint=FP
    )
    cited = dict(repository_id=repo.repository_id, file="Dockerfile", line=3, sha256=sha)
    review = dict(
        **identity,
        decisions=[
            dict(
                local_id="cfg-1",
                verdict="verified",
                reason="The whole file declares no runtime user.",
                evidence=[cited],
            )
        ],
    )
    ranges = [dict(repository_id=repo.repository_id, path="Dockerfile", sha256=sha, start_line=2, end_line=3)]
    allowed = frozenset({(repo.repository_id, "Dockerfile")})
    check = lambda: stage.validate_evidence_review(  # noqa: E731
        scope, [dict(local_id="cfg-1", evidence=anchor)], FP, review, ranges, allowed
    )
    if accepted:
        check()
    else:
        with pytest.raises(ExchangeError, match="independent reading"):
            check()


def test_local_architecture_returns_every_combined_flow_invariant_to_its_author(tmp_path):
    """Rules beyond the role check, here a human interaction aimed at a server, reach the analyst too."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    local = [dict(components[0], id="component-api")]
    artifact = _role_architecture(evidence[0], identity, ["none"], via_client=False, access="internet-anon")
    artifact["data_flows"][0]["interaction"] = True
    artifact["data_flows"][0].pop("authentication")
    with pytest.raises(ExchangeError, match="human interaction must target a client component"):
        stage.validate_local_architecture(
            scope,
            evidence[0]["repository_id"],
            dict(components=local + components[1:], source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )


@pytest.mark.parametrize(
    ("scheme", "entity_kind", "with_client"),
    [
        # The run that exposed it: a password login and a cookie request marked as interactions, no client at all.
        ("password", "legitimate-role", False),
        ("cookie", "legitimate-role", False),
        # The same flag on an unauthenticated server request, or from a non-human entity, beside a real client.
        (None, "legitimate-role", True),
        (None, "external-service", True),
    ],
)
def test_an_impossible_interaction_flag_is_removed_not_returned_for_correction(
    tmp_path, scheme, entity_kind, with_client
):
    """The controller knows every fact that decides an interaction; a wrong flag never costs a correction turn."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    local = [dict(components[0], id="component-api")]
    artifact = _role_architecture(evidence[0], identity, [scheme or "none"], via_client=False)
    if with_client:
        local.append(dict(components[0], id="component-ui", name="Browser client", tier="client"))
        artifact["data_flows"].append(
            dict(artifact["data_flows"][0], id="df-009", to="component-ui", interaction=True, authentication=None)
        )
        artifact["data_flows"][-1].pop("authentication")
    artifact["external_entities"][0]["kind"] = entity_kind
    artifact["data_flows"][0]["interaction"] = True
    if scheme is None:
        artifact["data_flows"][0].pop("authentication", None)
    validate = (
        lambda value: stage.validate_local_architecture(  # noqa: E731
            scope,
            evidence[0]["repository_id"],
            dict(components=local + components[1:], source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            value,
            ranges[:1],
        )
    )
    if entity_kind == "legitimate-role":
        with pytest.raises(ExchangeError, match="interaction"):
            validate(copy.deepcopy(artifact))
    normalize = stage.local_architecture_normalizer(local)
    fixed = normalize(copy.deepcopy(artifact))
    assert "interaction" not in fixed["data_flows"][0]
    # The flow stays an analyzed access with its own authentication claim.
    assert fixed["data_flows"][0].get("authentication") == artifact["data_flows"][0].get("authentication")
    assert normalize(copy.deepcopy(fixed)) == fixed
    if entity_kind == "legitimate-role":
        validate(fixed)
    if with_client:
        # A human-to-client interaction is kept; a non-human entity's is not.
        assert ("interaction" in fixed["data_flows"][-1]) is (entity_kind == "legitimate-role")


@pytest.mark.parametrize(("jobs", "used", "expected"), [(5, 0, 100), (2, 100, 200), (3, 500, 0), (600, 0, 1)])
def test_each_job_gets_its_share_of_a_combined_list_limit(jobs, used, expected):
    """Concatenated job lists can no longer exceed the combined contract that bounds them."""
    schema = stage.job_share(
        stage.contract("multi-repo-architecture.schema.json"),
        "fragments/data-flows-v2.schema.json",
        jobs=jobs,
        used={"data_flows": used},
    )
    assert schema["properties"]["data_flows"]["maxItems"] == expected
    assert schema["properties"]["external_entities"]["maxItems"] == -(-64 // jobs)
    assert stage.contract("multi-repo-architecture.schema.json")["properties"]["data_flows"]["maxItems"] == 500


@pytest.mark.parametrize("jobs", [3, 499, 500, 501, 800])
def test_jobs_that_fill_their_shares_never_exceed_the_combined_limit_or_starve_early(jobs):
    used, shares = 0, []
    for index in range(jobs):
        schema = stage.job_share(
            stage.contract("multi-repo-architecture.schema.json"),
            "fragments/data-flows-v2.schema.json",
            jobs=jobs - index,
            used={"data_flows": used},
        )
        share = schema["properties"]["data_flows"]["maxItems"]
        shares.append(share)
        used += share
    assert used <= 500
    # Every job may return an entry while the combined list has room for one.
    assert all(share >= 1 for share in shares[: min(jobs, 500)])


def test_local_group_names_of_two_repositories_never_join_their_flows():
    from orchestrator.orchestration_controller import _namespace_local_flow

    def local():
        return {
            "id": "df-001",
            "from": "external",
            "from_entity": "ext-client",
            "to": "component-api",
            "access_group": {"id": "inbound-api", "mode": "alternatives", "label": "Inbound API"},
            "protocol_group": "Sign-in",
        }

    first = _namespace_local_flow(local(), "repo-0000000000000001", "edge", {"ext-client": "ext-a"})
    second = _namespace_local_flow(local(), "repo-0000000000000002", "service", {"ext-client": "ext-b"})
    assert first["access_group"]["id"] != second["access_group"]["id"]
    assert first["protocol_group"] != second["protocol_group"]
    assert first["access_group"]["label"] == "Inbound API" and first["protocol_group"].startswith("Sign-in")


def test_a_local_flow_cannot_claim_a_reviewed_connection(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = _role_architecture(evidence[0], identity, ["none"], via_client=False, access="internet-anon")
    artifact["data_flows"][0]["connection_id"] = "connection-" + "a" * 16
    with pytest.raises(ExchangeError, match="reviewed cross-repository connection"):
        stage.validate_local_architecture(
            scope,
            evidence[0]["repository_id"],
            dict(
                components=[dict(components[0], id="component-api")] + components[1:],
                source_scope_sha256=identity["source_scope_sha256"],
            ),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )


@pytest.mark.parametrize(("kind", "rejected"), [("external-service", True), ("legitimate-role", False)])
def test_local_architecture_cannot_repeat_a_reviewed_call_as_an_external_service(tmp_path, kind, rejected):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    rid = evidence[0]["repository_id"]
    local = next(c for c in components if c["repository_ids"] == [rid])
    peer = dict(id="ext-peer", name="peer", kind=kind, description="Called peer.", evidence=[evidence[0]])
    flow = dict(
        id="df-001",
        **(
            {"from": local["id"], "to": "external", "to_entity": "ext-peer"}
            if kind != "legitimate-role"
            else {"from": "external", "from_entity": "ext-peer", "to": local["id"]}
        ),
        label="Peer call",
        protocol="HTTP",
        data_classification="unknown",
        direction="unidirectional",
        evidence=[evidence[0]],
        provenance="architecture",
    )
    artifact = dict(**identity, repository_id=rid, data_flows=[flow], external_entities=[peer], assets=[])
    reviewed = [dict(connection_id="connection-" + "a" * 16, evidence=[evidence[0]])]
    arguments = (
        scope,
        rid,
        dict(components=components, source_scope_sha256=identity["source_scope_sha256"]),
        dict(component_inventory_fingerprint=FP),
        artifact,
        ranges,
    )
    if rejected:
        with pytest.raises(ExchangeError, match="connection-a"):
            stage.validate_local_architecture(*arguments, reviewed)
    # Without a reviewed connection the same external call stays a valid local flow.
    assert stage._reviewed_call_flows(rid, artifact, []) == []
    assert stage._reviewed_call_flows(rid, artifact, reviewed) == (["connection-" + "a" * 16] if rejected else [])


def _file_targets(scope, files, lines=(1,)):
    rid = scope.repositories[0].repository_id
    return [
        {"local_id": f"surface-{path}-{line}", "evidence": {"repository_id": rid, "file": path, "line": line}}
        for path in files
        for line in lines
    ]


@pytest.mark.parametrize("prefix", ["routes", "handlers/v2"])
def test_target_jobs_follow_source_size_and_preload_every_window(tmp_path, prefix):
    files = {f"{prefix}/h{i:02d}.ts": b"export const handle = (req) => req.body\n" for i in range(20)}
    scope, _ = _owned_sources(tmp_path, files, sorted(files))
    targets = _file_targets(scope, sorted(files))
    # Twenty small windows are one job when they fit, not ceil(20 / 6) jobs.
    roomy = stage.target_batches(
        scope, targets, room=100_000, max_targets=64, max_windows=36, window_lines=400, max_unserved=6
    )
    assert len(roomy) == 1 and len(roomy[0][1]) == 20
    tight = stage.target_batches(
        scope, targets, room=1_500, max_targets=64, max_windows=36, window_lines=400, max_unserved=6
    )
    assert 1 < len(tight) < 20
    for batch in (roomy, tight):
        assert sorted(t["local_id"] for part, _ in batch for t in part) == sorted(t["local_id"] for t in targets)
        assert all(len(preload) == len({t["evidence"]["file"] for t in part}) for part, preload in batch)


@pytest.mark.parametrize("reserve_bytes,reserve_windows", [(1_000, 0), (0, 32)], ids=["bytes", "windows"])
def test_only_the_first_target_job_reserves_room_for_context_lines(tmp_path, reserve_bytes, reserve_windows):
    files = {f"routes/h{i:02d}.ts": b"export const handle = (req) => req.body\n" for i in range(20)}
    scope, _ = _owned_sources(tmp_path, files, sorted(files))
    targets = _file_targets(scope, sorted(files))
    arguments = dict(room=2_500, max_targets=64, max_windows=36, window_lines=400, max_unserved=6)
    plain = stage.target_batches(scope, targets, **arguments)
    reserved = stage.target_batches(
        scope, targets, **arguments, reserve_bytes=reserve_bytes, reserve_windows=reserve_windows
    )
    # The first job holds fewer windows; every later job keeps its full room.
    assert len(reserved[0][1]) < len(plain[0][1])
    assert all(len(preload) == len(plain[1][1]) for _, preload in reserved[1:-1])
    assert sorted(t["local_id"] for part, _ in reserved for t in part) == sorted(t["local_id"] for t in targets)


def test_targets_sharing_a_window_stay_together_and_oversized_windows_are_left_to_the_model(tmp_path):
    files = {"server.ts": b"app.get('/a', a)\n" * 50, "big.ts": b"const x = '" + b"y" * 5_000 + b"'\n"}
    scope, _ = _owned_sources(tmp_path, files, sorted(files))
    targets = _file_targets(scope, ["server.ts"], lines=range(1, 40, 3)) + _file_targets(scope, ["big.ts"])
    batches = stage.target_batches(
        scope, targets, room=3_000, max_targets=64, max_windows=36, window_lines=400, max_unserved=6
    )
    server = [part for part, _ in batches if any(t["evidence"]["file"] == "server.ts" for t in part)]
    assert len(server) == 1 and sum(t["evidence"]["file"] == "server.ts" for t in server[0]) == 13
    # A window larger than the room is not preloaded; the model reads it within its own allowance.
    assert all(key[1] != "big.ts" for _, preload in batches for key in preload)


def test_a_window_with_more_targets_than_one_job_decides_is_split(tmp_path):
    scope, _ = _owned_sources(tmp_path, {"server.ts": b"app.get('/a', a)\n" * 50}, ["server.ts"])
    targets = _file_targets(scope, ["server.ts"], lines=range(1, 40, 3))
    batches = stage.target_batches(
        scope, targets, room=100_000, max_targets=5, max_windows=36, window_lines=400, max_unserved=6
    )
    assert [len(part) for part, _ in batches] == [5, 5, 3]
    assert all(len(preload) == 1 for _, preload in batches)


def test_a_job_preloads_at_most_its_window_limit(tmp_path):
    files = {f"h{i:02d}.ts": b"export const handle = 1\n" for i in range(9)}
    scope, _ = _owned_sources(tmp_path, files, sorted(files))
    batches = stage.target_batches(
        scope,
        _file_targets(scope, sorted(files)),
        room=100_000,
        max_targets=64,
        max_windows=4,
        window_lines=400,
        max_unserved=6,
    )
    assert [len(preload) for _, preload in batches] == [4, 4, 1]


def _route(route_id, method, path, file, line):
    return {"route_id": route_id, "method": method, "path": path, "handler_file": file, "handler_line": line}


@pytest.mark.parametrize(
    "registration,handler", [("server.ts", "routes/items.ts"), ("src/app.js", "handlers/v2/catalog.js")]
)
def test_a_resolved_route_resource_is_one_target_at_its_handler_with_its_guards(tmp_path, registration, handler):
    """MR-13: collection and item routes are one decision, read beside their registration lines."""
    files = {
        registration: (
            b"const app = express()\n"
            b"app.get('/api/Items', items.list())\n"
            b"app.put('/api/Items/:id', security.denyAll())\n"
            b"app.get('/rest/login', login())\n"
        ),
        handler: b"export const list = () => (req, res) => db.query(req.query)\n",
    }
    scope, component = _owned_sources(tmp_path, files, sorted(files))
    rid = scope.repositories[0].repository_id
    architecture = {
        "data_flows": {"data_flows": []},
        "route_inventories": {
            rid: {
                "routes": [
                    _route("R-1", "GET", "/api/Items", registration, 2),
                    _route("R-2", "PUT", "/api/Items/:id", registration, 3),
                    _route("R-3", "GET", "/rest/login", registration, 4),
                ]
            }
        },
        "route_handler_modules": {rid: {"R-1": handler}},
    }
    targets = stage.analysis_targets(scope, component, architecture, [])
    by_file = {t["evidence"]["file"]: t for t in targets}
    assert len(targets) == 2 and set(by_file) == {registration, handler}
    resource = by_file[handler]
    assert resource["kinds"] == ["route"]
    assert [(r["method"], r["path"]) for r in resource["routes"]] == [("GET", "/api/Items"), ("PUT", "/api/Items/:id")]
    assert resource["related"] == [[rid, registration, 1, 399]]
    # A resource without a resolved handler, here the inline login, stays at its registration.
    assert by_file[registration]["evidence"]["line"] == 4
    assert [r["path"] for r in by_file[registration]["routes"]] == ["/rest/login"]
    # Even a job holding only the handler preloads the registration window with its guards.
    batches = stage.target_batches(
        scope, targets, room=100_000, max_targets=1, max_windows=36, window_lines=400, max_unserved=6
    )
    handler_job = next(preload for part, preload in batches if part[0]["evidence"]["file"] == handler)
    assert {key[1] for key in handler_job} == {handler, registration}
    login_job = next(preload for part, preload in batches if part[0]["evidence"]["file"] == registration)
    assert [key[1] for key in login_job] == [registration]


@pytest.mark.parametrize(
    ("handler", "helper", "spec"),
    [
        ("routes/redirect.ts", "lib/allow.ts", "../lib/allow"),
        ("api/v2/upload.js", "shared/xml/parse.js", "../../shared/xml/parse"),
    ],
)
def test_imported_helper_of_another_component_is_readable(tmp_path, handler, helper, spec):
    """MR-19: a target may read the files its file imports, whichever component owns them, unpreloaded."""
    files = {
        handler: f"import {{ check }} from '{spec}'\nimport express from 'express'\n"
        f"export const go = (req, res) => check(req.query.to) && res.redirect(req.query.to)\n".encode(),
        helper: b"export const check = (url) => url.includes('example.invalid')\n",
        "lib/unused.ts": b"export const other = 1\n",
    }
    scope, component = _owned_sources(tmp_path, files, [handler])
    rid = scope.repositories[0].repository_id
    architecture = {"data_flows": {"data_flows": []}, "route_inventories": {}, "route_handler_modules": {}}
    [target] = [
        t for t in stage.analysis_targets(scope, component, architecture, []) if t["evidence"]["file"] == handler
    ]
    assert target["imports"] == [[rid, helper]]
    assert stage.related_sources([target]) == {(rid, helper)}
    # Authorized, never preloaded: no related window names the helper.
    assert all(row[1] != helper for row in target.get("related", []))


def test_guard_registration_outside_the_route_window_is_related(tmp_path):
    """MR-19: a guard registered far above its route is named, so the job can read it."""
    registration = "server.ts"
    files = {
        registration: b"const app = express()\n"
        + b"app.use('/rest/account', guard())\n"
        + b"\n" * 600
        + b"app.get('/rest/account/details', details())\n",
        "routes/details.ts": b"export const details = () => (req, res) => res.json(req.user)\n",
    }
    scope, component = _owned_sources(tmp_path, files, sorted(files))
    rid = scope.repositories[0].repository_id
    route = {**_route("R-1", "GET", "/rest/account/details", registration, 603), "guard_lines": [2]}
    architecture = {
        "data_flows": {"data_flows": []},
        "route_inventories": {rid: {"routes": [route]}},
        "route_handler_modules": {rid: {"R-1": "routes/details.ts"}},
    }
    by_file = {t["evidence"]["file"]: t for t in stage.analysis_targets(scope, component, architecture, [])}
    resource = by_file["routes/details.ts"]
    assert resource["guard_lines"] == [[rid, registration, 2]]
    # The registration window (lines 400-799) misses the guard; the file stays readable.
    assert resource["related"] == [[rid, registration, 400, 799]]
    assert (rid, registration) in stage.related_sources([resource])
    # Without a guard the target names none.
    route.pop("guard_lines")
    assert (
        "guard_lines"
        not in {t["evidence"]["file"]: t for t in stage.analysis_targets(scope, component, architecture, [])}[
            "routes/details.ts"
        ]
    )


@pytest.mark.parametrize("registration,handler", [("server.ts", "routes/login.ts"), ("src/app.js", "auth/session.js")])
def test_a_route_is_decided_by_the_component_that_owns_its_handler(tmp_path, registration, handler):
    """MR-13 across components: the handler's owner decides the route and reads its registration guards."""
    files = {
        registration: (
            b"const app = express()\n"
            b"app.post('/rest/user/login', login())\n"
            b"app.get('/rest/health', (req, res) => res.send('ok'))\n"
        ),
        handler: b"export const login = () => (req, res) => db.query(req.body.email)\n",
    }
    scope, server = _owned_sources(tmp_path, files, [registration])
    rid = scope.repositories[0].repository_id
    auth = dict(server, id="component-2", name="Auth", paths=[dict(repository_id=rid, path=handler)])
    architecture = {
        "components": {"components": [server, auth]},
        "data_flows": {"data_flows": []},
        "route_inventories": {
            rid: {
                "routes": [
                    _route("R-1", "POST", "/rest/user/login", registration, 2),
                    _route("R-2", "GET", "/rest/health", registration, 3),
                ]
            }
        },
        "route_handler_modules": {rid: {"R-1": handler}},
    }
    lead = {"evidence": {"repository_id": rid, "file": registration, "line": 2}}
    server_targets = stage.analysis_targets(scope, server, architecture, [lead])
    # The registration file keeps only the route it decides itself; the lead on
    # the login registration belongs to the handler owner's decision.
    assert [(t["evidence"]["line"], [r["path"] for r in t["routes"]]) for t in server_targets] == [
        (3, ["/rest/health"])
    ]
    auth_targets = stage.analysis_targets(scope, auth, architecture, [])
    (target,) = auth_targets
    assert target["evidence"]["file"] == handler
    assert [r["path"] for r in target["routes"]] == ["/rest/user/login"]
    assert target["related"] == [[rid, registration, 1, 399]]
    assert stage.related_sources(auth_targets) == {(rid, registration)}
    batches = stage.target_batches(
        scope, auth_targets, room=100_000, max_targets=64, max_windows=36, window_lines=400, max_unserved=6
    )
    assert {key[1] for _, preload in batches for key in preload} == {handler, registration}
    # A handler module no finalized component owns leaves the route at its registration.
    orphan = {**architecture, "components": {"components": [server]}}
    assert sorted(r["path"] for t in stage.analysis_targets(scope, server, orphan, []) for r in t["routes"]) == [
        "/rest/health",
        "/rest/user/login",
    ]


@pytest.mark.parametrize(
    "registration,handler", [("server.ts", "routes/items.ts"), ("src/app.js", "handlers/v2/catalog.js")]
)
def test_a_scanner_lead_on_a_registration_line_joins_its_route_decision(tmp_path, registration, handler):
    files = {
        registration: (
            b"const app = express()\n"
            b"app.get('/api/Items', items.list())\n"
            b"const sessionSecret = process.env.SECRET || 'fallback'\n"
        ),
        handler: b"export const list = () => (req, res) => db.query(req.query)\n",
    }
    scope, component = _owned_sources(tmp_path, files, sorted(files))
    rid = scope.repositories[0].repository_id
    architecture = {
        "data_flows": {"data_flows": []},
        "route_inventories": {rid: {"routes": [_route("R-1", "GET", "/api/Items", registration, 2)]}},
        "route_handler_modules": {rid: {"R-1": handler}},
    }

    def lead(line):
        return {"evidence": {"repository_id": rid, "file": registration, "line": line}}

    targets = stage.analysis_targets(scope, component, architecture, [lead(2), lead(3)])
    by_anchor = {(t["evidence"]["file"], t["evidence"]["line"]): t for t in targets}
    # The registration-line lead is decided with the handler that reads the guards beside it.
    assert (registration, 2) not in by_anchor
    assert by_anchor[(handler, 1)]["kinds"] == ["route", "scanner-lead"]
    # A lead on any other line stays its own target.
    assert by_anchor[(registration, 3)]["kinds"] == ["scanner-lead"]


@pytest.mark.parametrize(
    "script,reference,template",
    [
        ("src/app/about/about.component.ts", "./about.component.html", "src/app/about/about.component.html"),
        ("web/views/panel.js", "../templates/panel.html", "web/templates/panel.html"),
    ],
)
def test_a_component_and_its_template_are_read_together(tmp_path, script, reference, template):
    """MR-13: logic and markup decide an output sink together, from either side."""
    files = {
        script: f"@Component({{ templateUrl: '{reference}' }})\nexport class View {{ html = this.render(input) }}\n".encode(),
        template: b'<div [innerHTML]="html"></div>\n',
        "src/inline.component.ts": b"@Component({ template: '<b>{{ x }}</b>' })\nexport class Inline { x = input }\n",
    }
    scope, component = _owned_sources(tmp_path, files, sorted(files))
    rid = scope.repositories[0].repository_id

    def lead(path):
        return {"evidence": {"repository_id": rid, "file": path, "line": 2 if path != template else 1}}

    architecture = {"data_flows": {"data_flows": []}}
    for start, other in ((script, template), (template, script)):
        (target,) = [
            t
            for t in stage.analysis_targets(scope, component, architecture, [lead(start)])
            if t["evidence"]["file"] == start
        ]
        assert target["related"] == [[rid, other, 1, 399]]
    # An inline template names no file, so nothing is related.
    (inline,) = [
        t
        for t in stage.analysis_targets(scope, component, architecture, [lead("src/inline.component.ts")])
        if t["evidence"]["file"] == "src/inline.component.ts"
    ]
    assert "related" not in inline


@pytest.mark.parametrize("path,line", [("routes/basket.ts", 19), ("svc/orders/handler.py", 4)])
def test_a_coverage_decision_with_a_finding_needs_no_reason(path, line):
    """MR-11: a linked finding states the reason; every other decision states its own, and the anchor is inserted."""
    from runtime.assessment_host import Rejection

    anchor = {"repository_id": "repo-" + "1" * 16, "file": path, "line": line, "sha256": "a" * 64}
    target = {"local_id": "surface-" + "b" * 16, "evidence": anchor}
    ranges = [
        {"repository_id": anchor["repository_id"], "path": path, "sha256": "a" * 64, "start_line": 1, "end_line": 99}
    ]
    item = Draft202012Validator(
        stage.contract("multi-repo-stride.schema.json")["properties"]["surface_coverage"]["items"]
    )
    normalize = stage.surface_evidence_normalizer([target])

    def decided(**row):
        artifact = {"threats": [{"local_id": "f-1"}], "surface_coverage": [{"target_id": target["local_id"], **row}]}
        assert item.is_valid(artifact["surface_coverage"][0])
        artifact = normalize(artifact)
        stage.validate_surface_coverage(artifact, ranges, [target])
        return artifact["surface_coverage"][0]

    linked = decided(
        disposition="examined", finding_ids=["f-1"], reason="The handler reads the basket without an owner check."
    )
    assert "reason" not in linked and linked["evidence"] == [anchor]
    assert decided(disposition="unresolved", finding_ids=[], reason="The guard module was not read.")["evidence"] == [
        anchor
    ]
    for disposition in ("examined", "not-applicable", "unresolved"):
        with pytest.raises(Rejection, match="needs a reason"):
            decided(disposition=disposition, finding_ids=[])
    # A reason stays one short sentence.
    assert not item.is_valid(
        {"target_id": target["local_id"], "disposition": "unresolved", "finding_ids": [], "reason": "x" * 161}
    )


@pytest.mark.parametrize(
    "path,resource",
    [
        ("/api/Users/:id/orders", "/api/Users"),
        ("/users/{user_id}", "/users"),
        ("/files/<name>", "/files"),
        ("/assets/*", "/assets"),
        # A path without parameters is its own resource, so distinct actions stay apart.
        ("/rest/user/login", "/rest/user/login"),
    ],
)
def test_route_resources_end_at_the_first_parameter(path, resource):
    assert stage.route_resource(path) == resource


@pytest.mark.parametrize(
    "acl", [b"export function checkPermission(user) {}\n", b"def custom_permission_check(): pass\n"]
)
def test_a_file_without_a_security_signal_is_reported_instead_of_targeted(tmp_path, acl):
    files = {
        "lib/format.ts": b"export const pad = (s) => s.padStart(2)\n",
        "lib/acl.code": acl,
        "views/card.html": b'<div [innerHTML]="text"></div>\n',
    }
    scope, component = _owned_sources(tmp_path, files, sorted(files))
    targets = stage.analysis_targets(scope, component, {"data_flows": {"data_flows": []}}, [])
    # Authorization logic in an identifier and a template sink are signals; formatting is not.
    assert {t["evidence"]["file"] for t in targets} == {"lib/acl.code", "views/card.html"}
    assert stage.unexamined_files(component, targets) == [(scope.repositories[0].repository_id, "lib/format.ts")]


def test_program_files_outside_every_component_are_summarised_by_directory(tmp_path):
    files = {
        "src/api.ts": b"x\n",
        "lib/parse.ts": b"x\n",
        "lib/sub/hash.py": b"x\n",
        "tools/build.js": b"x\n",
        "lib/parse.test.ts": b"x\n",
        "tests/api_test.py": b"x\n",
        "docs/guide.md": b"x\n",
        "config.json": b"{}\n",
    }
    scope, component = _owned_sources(tmp_path, files, ["src/api.ts"])
    assert stage.unowned_summary(scope, [component], lambda rid, path: path) == {
        "files": 3,
        "by_directory": [{"directory": "lib/", "files": 2}, {"directory": "tools/", "files": 1}],
    }
    assert (
        stage.unowned_summary(
            scope,
            [
                {
                    **component,
                    "paths": component["paths"]
                    + [
                        {"repository_id": component["repository_ids"][0], "path": p}
                        for p in ("lib/parse.ts", "lib/sub/hash.py", "tools/build.js")
                    ],
                }
            ],
            lambda rid, path: path,
        )
        is None
    )


def test_evidence_preload_serves_cited_ranges_inside_the_job_bounds(tmp_path):
    files = {"a.ts": b"".join(b"line_%d()\n" % n for n in range(1, 301)), "foreign.ts": b"x()\n"}
    scope, component = _owned_sources(tmp_path, files, ["a.ts"])
    rid = scope.repositories[0].repository_id
    allowed = stage.source_selection([component])
    cited = [
        {"repository_id": rid, "file": "a.ts", "line": 10},
        {"repository_id": rid, "file": "a.ts", "line": 50},
        {"repository_id": rid, "file": "a.ts", "line": 260},
        {"repository_id": rid, "file": "foreign.ts", "line": 1},
    ]
    # Overlapping ranges merge, the end clamps to the file, and an unselected file is never served.
    assert stage.evidence_preload(scope, cited, allowed, room=100_000, max_windows=36) == [
        (rid, "a.ts", 1, 140),
        (rid, "a.ts", 230, 300),
    ]
    assert stage.evidence_preload(scope, cited, allowed, room=100_000, max_windows=1) == [(rid, "a.ts", 1, 140)]
    assert stage.evidence_preload(scope, cited, allowed, room=100, max_windows=36) == []


def test_model_components_drop_only_the_path_hashes(tmp_path):
    scope, components, _, _, _ = sources(tmp_path)
    original = copy.deepcopy(components)
    view = stage.model_components(components)
    assert components == original
    assert [row for c in view for row in c["paths"]] == [
        {k: v for k, v in row.items() if k != "sha256"} for c in original for row in c["paths"]
    ]
    assert all(
        {k: v for k, v in c.items() if k != "paths"} == {k: v for k, v in o.items() if k != "paths"}
        for c, o in zip(view, original, strict=True)
    )


@pytest.mark.parametrize("line,problem", [(2, "blank"), (3, "comment")])
def test_a_non_executable_finding_anchor_is_named_for_an_anchor_only_correction(tmp_path, line, problem):
    from runtime.assessment_host import Rejection

    source = b"result = request.args['input']\n\n# Blocking sleep helper\nsleep(result)\n"
    repo = RepositoryView("repo-" + "1" * 16, tmp_path / "repo", "b" * 40, "c" * 64, {"app.py": source})
    scope = AssessmentScope((repo,), tmp_path / "output")
    digest = hashlib.sha256(source).hexdigest()
    component = dict(
        id="component-1",
        name="Service",
        tier="application",
        repository_ids=[repo.repository_id],
        paths=[dict(repository_id=repo.repository_id, path="app.py", sha256=digest)],
    )
    evidence = dict(repository_id=repo.repository_id, file="app.py", line=line, sha256=digest)
    identity = dict(
        schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], component_inventory_fingerprint=FP
    )
    ranges = [dict(repository_id=repo.repository_id, path="app.py", sha256=digest, start_line=1, end_line=4)]
    flows = dict(component_inventory_fingerprint=FP, data_flows=[])
    with pytest.raises(Rejection) as raised:
        stage.validate_stride(scope, component, [component], flows, stride(component, evidence, identity), ranges)
    assert problem in str(raised.value)
    assert [row["line"] for row, _ in raised.value.anchors] == [line]
    # An executable anchor passes the same validation.
    stage.validate_stride(
        scope, component, [component], flows, stride(component, {**evidence, "line": 1}, identity), ranges
    )


@pytest.mark.parametrize(
    "damage",
    ["coverage-mismatch", "missing-category", "stale-identity"],
)
def test_stride_coverage_and_identity_are_derived_before_validation(tmp_path, damage):
    """MR-17: what the controller knows is set, not checked and returned to the model."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    component = components[0]
    artifact = stride(component, evidence[0], identity)
    flows = dict(component_inventory_fingerprint=FP, data_flows=[])
    if damage == "coverage-mismatch":
        artifact["coverage"] = [dict(row, disposition="no-evidence", finding_ids=[]) for row in artifact["coverage"]]
    elif damage == "missing-category":
        artifact["coverage"] = [row for row in artifact["coverage"] if row["category"] != "Tampering"]
    else:
        artifact.update(component_name="Renamed", source_scope_sha256="0" * 64)
    with pytest.raises(ExchangeError):
        stage.validate_stride(scope, component, [component], flows, copy.deepcopy(artifact), ranges[:1])
    normalized = stage.stride_normalizer([], component, identity)(copy.deepcopy(artifact))
    stage.validate_stride(scope, component, [component], flows, normalized, ranges[:1])
    tampering = next(row for row in normalized["coverage"] if row["category"] == "Tampering")
    assert tampering["disposition"] == "finding" and tampering["finding_ids"] == ["issue-1"]
    assert [row["category"] for row in normalized["coverage"]] == list(stage.STRIDE_CATEGORIES)


@pytest.mark.parametrize(
    "title,expected",
    [
        ("Unvalidated input reaches the handler (old/place.py:99)", "Unvalidated input reaches the handler (app.py:1)"),
        ("Unvalidated input reaches the handler", "Unvalidated input reaches the handler (app.py:1)"),
        ("A" * 75, "A" * 75),
    ],
    ids=["replaced", "added", "dropped-when-too-long"],
)
def test_a_title_location_comes_from_its_anchor(tmp_path, title, expected):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    artifact["threats"][0]["title"] = title
    normalized = stage.stride_normalizer([], components[0], identity)(artifact)
    assert normalized["threats"][0]["title"] == expected and len(expected) <= stage.TITLE_MAX


def test_the_control_job_may_only_choose_a_placeable_domain():
    """MR-17 (RC-L): the output tool enforces the §6 domains `validate_controls` accepts."""
    from jsonschema import Draft202012Validator

    schema = stage.controls_contract()
    domain = schema["properties"]["security_controls"]["items"]["properties"]["domain"]
    assert domain["enum"] == list(stage._placeable_domains())
    assert not stage._unplaced_controls(
        [
            dict(control="x", effectiveness="Weak", component_ids=[], evidence=[], assessment="-", domain=d)
            for d in domain["enum"]
        ]
    )
    assert not Draft202012Validator(domain).is_valid("Recovery")


@pytest.mark.parametrize("handler,helper", [("routes/read.ts", "lib/parser.ts"), ("api/get.js", "shared/check.js")])
def test_supporting_sources_close_guard_and_helper_gaps_without_more_jobs(tmp_path, handler, helper):
    import posixpath

    spec = posixpath.relpath(helper, posixpath.dirname(handler))
    files = {
        "entry.ts": b"const app = express()\n"
        + b"\n" * 396
        + b"app.use('/records', authorize())\n"
        + b"\n" * 202
        + b"app.get('/records', read())\n",
        handler: f"import {{ parse }} from '{spec}'\nexport const read = req => parse(req.body.xml)\n".encode(),
        helper: b"export const parse = xml => parser.parse(xml, { resolveEntities: true })\n",
        "lib/unrelated.ts": b"export const secret = 'unrelated-private-data'\n",
    }
    scope, component = _owned_sources(tmp_path, files, [handler, "entry.ts"])
    rid = scope.repositories[0].repository_id
    target = {
        "local_id": "surface-read",
        "evidence": {"repository_id": rid, "file": handler, "line": 2},
        "related": [[rid, "entry.ts", 400, 799]],
        "guard_lines": [[rid, "entry.ts", 398]],
        "imports": [[rid, helper]],
        "routes": [{"line": 601, "path": "/records"}],
    }
    batches = stage.target_batches(
        scope, [target], room=100_000, max_targets=64, max_windows=36, window_lines=400, max_unserved=6
    )
    assert len(batches) == 1
    allowed = stage.source_selection([component]) | stage.related_sources([target])
    original = batches[0][1]
    supplied = stage.supporting_preload(scope, [target], original, allowed, context={})
    assert not any(p[1] == "entry.ts" and p[2] <= 398 <= p[3] for p in original)
    assert any(p[1] == "entry.ts" and p[2] <= 398 <= p[3] for p in supplied)
    assert any(p[1] == helper for p in supplied)
    assert all(p[1] != "lib/unrelated.ts" for p in supplied)
    assert supplied[: len(original)] == original and len(batches) == 1
    assert stage.served_bytes(scope, supplied) - stage.served_bytes(scope, original) <= stage.MAX_SUPPORT_BYTES
    # Existing control code remains visible too; reads do not imply a vulnerability.
    assert "authorize()" in "\n".join(text for p in supplied for text in stage.read_slice(scope, *p)["lines"])
    # Reapplying the supplement never duplicates source or spends more budget.
    assert stage.supporting_preload(scope, [target], supplied, allowed, context={}) == supplied


@pytest.mark.parametrize("limit", ["bytes", "windows", "authority"])
def test_supporting_sources_respect_capacity_and_read_authority(tmp_path, limit):
    files = {"entry.ts": b"authorize()\n" * 700, "private.ts": b"secret()\n"}
    scope, component = _owned_sources(tmp_path, files, ["entry.ts"])
    rid = scope.repositories[0].repository_id
    target = {
        "evidence": {"repository_id": rid, "file": "entry.ts", "line": 601},
        "guard_lines": [[rid, "private.ts", 1]],
    }
    original = [(rid, "entry.ts", 400, 700)]
    context = {}
    if limit == "bytes":
        context = {"already_supplied": "x" * 253_000}
    elif limit == "windows":
        original = [(rid, "entry.ts", n, n) for n in range(601, 637)]
    allowed = stage.source_selection([component])
    supplied = stage.supporting_preload(scope, [target], original, allowed, context=context)
    assert supplied == original


def test_supporting_sources_do_not_spend_the_budget_on_overlap_or_one_large_import(tmp_path):
    files = {
        "handler.ts": b"import { authorize } from './aaa-large'\n"
        b"import { parse } from './zzz-parser'\nparse(request.body)\n",
        "entry.ts": b"authorize()\n" * 700,
        "aaa-large.ts": b"authorize(request)\n" * 900,
        "zzz-parser.ts": b"export const parse = xml => parser.parse(xml, { resolveEntities: true })\n",
    }
    scope, component = _owned_sources(tmp_path, files, ["handler.ts", "entry.ts", "aaa-large.ts"])
    rid = scope.repositories[0].repository_id
    target = {
        "evidence": {"repository_id": rid, "file": "handler.ts", "line": 3},
        "guard_lines": [[rid, "entry.ts", 398], [rid, "entry.ts", 399]],
    }
    original = [(rid, "handler.ts", 1, 3), (rid, "entry.ts", 1, 399), (rid, "entry.ts", 400, 700)]
    owned = stage.source_selection([component])
    supplied = stage.supporting_preload(
        scope, [target], original, owned | {(rid, "zzz-parser.ts")}, context={}, component_sources=owned
    )
    extra = supplied[len(original) :]
    assert extra[0][1] == "zzz-parser.ts"
    assert all(p[1] != "entry.ts" for p in extra)
    assert any(p[1] == "aaa-large.ts" for p in extra)
    assert len(extra) <= stage.MAX_SUPPORT_WINDOWS
    assert stage.served_bytes(scope, supplied) - stage.served_bytes(scope, original) <= stage.MAX_SUPPORT_BYTES
    for i, p in enumerate(supplied):
        assert not any(p[:2] == q[:2] and max(p[2], q[2]) <= min(p[3], q[3]) for q in supplied[i + 1 :])


def test_review_targets_follow_exact_registration_and_mechanism_sources(tmp_path):
    rid = "repo-" + "1" * 16

    def target(file, line):
        return {
            "evidence": {"repository_id": rid, "file": file, "line": 1},
            "related": [[rid, "entry.ts", 400, 799]],
            "routes": [{"line": line}],
        }

    read, write = target("read.ts", 601), target("write.ts", 602)
    finding = {
        "evidence": {"repository_id": rid, "file": "entry.ts", "line": 601},
        "mechanism_trace": {"input": {"repository_id": rid, "file": "input.ts", "line": 4}},
    }
    chosen = stage.review_targets([finding], [read, write])
    assert read in chosen and write not in chosen
    assert any(t["evidence"]["file"] == "input.ts" for t in chosen)
    assert stage.review_targets([], [read, write]) == []


def test_stride_accepts_bounded_action_title_and_preserves_it_in_legacy_projection(tmp_path):
    from model.build_threat_model_yaml import build_mitigations
    from orchestrator.assessment_workspace import Namespaces, project_document

    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    title = "Validate request fields before processing"
    artifact["threats"][0]["mitigation_title"] = title
    schema = stage.contract("multi-repo-stride.schema.json")
    assert Draft202012Validator(schema).is_valid(artifact)
    assert stage._comparison(artifact)["threats"][0]["mitigation_title"] == title
    projected = project_document(artifact, Namespaces(scope))
    finding = {**projected["threats"][0], "id": "T-001"}
    assert build_mitigations([finding])[0]["title"] == title
    artifact["threats"][0]["mitigation_title"] = "x" * 81
    assert not Draft202012Validator(schema).is_valid(artifact)
