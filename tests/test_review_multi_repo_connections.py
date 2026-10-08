"""Only reviewed, scoped connections enter the canonical multi-repo graph."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts import review_multi_repo_connections as review
from contexts.reconcile_multi_repo_architecture import reconcile
from model.finalize_component_inventory import finalize_assessment
from runtime.analyst_host import HostReply
from runtime.assessment_host import MARKER, ExchangeError
from runtime.multi_repo_discovery import DiscoveryBudget
from runtime.multi_repo_scope import admit
from validators.validate_assessment_architecture import AssessmentArchitectureError, validate_flows


def fixture(tmp_path, protocol="HTTP", names=("edge", "service"), separate=False):
    roots = []
    for index, name in enumerate(names):
        root = tmp_path / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "initial",
            ],
            check=True,
        )
        deployment = "system-b" if separate and index else "system-a"
        operation = f"/records-{index // 2}" if len(names) > 2 else "/records"
        (root / "app.py").write_text(
            f'endpoint = "service:8080"; deployment = "{deployment}"; operation = "{operation}"\n'
        )
        (root / "extra.py").write_text("def enforce_identity(): return True\n")
        roots.append(str(root))
    scope = admit(roots, str(tmp_path / "out"))
    documents = []
    for index, repo in enumerate(scope.repositories):
        text = repo.files["app.py"].decode().strip()
        documents.append(
            {
                "schema_version": 1,
                "repository_id": repo.repository_id,
                "components": [
                    {
                        "id": "service",
                        "name": repo.root.name,
                        "description": "Application service",
                        "tier": "application",
                        "paths": ["app.py"],
                    }
                ],
                "interfaces": [
                    {
                        "id": "interface",
                        "component_id": "service",
                        "role": ("publish" if index % 2 == 0 else "consume")
                        if protocol == "Kafka"
                        else ("request" if index % 2 == 0 else "serve"),
                        "protocol": protocol,
                        "address": "service:8080",
                        "deployment": "system-b" if separate and index else "system-a",
                        "operation": f"/records-{index // 2}" if len(names) > 2 else "/records",
                        "evidence": [{"file": "app.py", "line": 1, "quote": text}],
                    }
                ],
            }
        )
    components, receipt = finalize_assessment(scope, documents)
    candidates = reconcile(scope, documents)
    result = {
        "schema_version": 1,
        "scope_sha256": candidates["scope_sha256"],
        "candidates_sha256": review.fingerprint(candidates),
        "component_inventory_fingerprint": receipt["component_inventory_fingerprint"],
        "decisions": [
            {
                "candidate_id": c["id"],
                "disposition": "resolved",
                "reason": "Both configured endpoint operations address the same deployment binding.",
                "evidence": [
                    {"repository_id": d["repository_id"], **d["interfaces"][0]["evidence"][0]}
                    for d in documents
                    if any(
                        i["repository_id"] == d["repository_id"]
                        and i["id"] in {c["sender_interface"], c["receiver_interface"]}
                        for i in candidates["interfaces"]
                    )
                ],
            }
            for c in candidates["candidates"]
        ],
    }
    return scope, documents, components, receipt, result


@pytest.mark.parametrize("names", [("edge", "service"), ("ingress", "processor")])
def test_reviewed_http_link_preserves_both_source_owners(tmp_path, names):
    args = fixture(tmp_path, names=names)
    before = copy.deepcopy(args[2:])
    components, receipt, flows = review.promote(*args)
    assert args[2:] == before
    assert len(flows["data_flows"]) == 1
    flow = flows["data_flows"][0]
    assert {e["repository_id"] for e in flow["evidence"]} == {r.repository_id for r in args[0].repositories}
    assert flow["deployment_activation"] == "unknown" and "authentication" not in flow
    validate_flows(args[0], components, receipt, flows)


def test_message_link_retains_broker_and_per_hop_sources(tmp_path):
    scope, documents, components, receipt, decision = fixture(tmp_path, protocol="Kafka")
    components, receipt, flows = review.promote(scope, documents, components, receipt, decision)
    broker = next(c for c in components["components"] if c["tier"] == "data")
    assert set(broker["repository_ids"]) == {r.repository_id for r in scope.repositories}
    first, second = flows["data_flows"]
    assert first["to"] == broker["id"] == second["from"]
    assert first["from"] != second["to"]
    assert first["evidence"][0]["repository_id"] != second["evidence"][0]["repository_id"]
    assert len(receipt["component_ids"]) == 3


def test_two_reviewed_topics_share_only_the_evidenced_broker(tmp_path):
    args = fixture(tmp_path, protocol="Kafka", names=("alpha", "bravo", "charlie", "delta"))
    components, receipt, flows = review.promote(*args)
    assert len(args[-1]["decisions"]) == 2
    brokers = [c for c in components["components"] if c["tier"] == "data"]
    assert len(brokers) == 1 and len(brokers[0]["repository_ids"]) == 4
    assert len(flows["data_flows"]) == 4
    assert len(receipt["injected_component_ids"]) == 1


@pytest.mark.parametrize("status", ["unresolved", "rejected"])
def test_unresolved_or_rejected_candidate_never_becomes_a_flow(tmp_path, status):
    args = fixture(tmp_path)
    args[-1]["decisions"][0]["disposition"] = status
    components, _, flows = review.promote(*args)
    assert len(components["components"]) == 2 and flows["data_flows"] == []


def test_equal_endpoints_in_separate_deployments_stay_disconnected(tmp_path):
    args = fixture(tmp_path, separate=True)
    assert args[-1]["decisions"] == []
    assert review.promote(*args)[2]["data_flows"] == []


@pytest.mark.parametrize(
    "kind", ["missing", "duplicate", "foreign", "quote", "one-sided", "scope", "fingerprint", "components"]
)
def test_invalid_review_cannot_promote_a_connection(tmp_path, kind):
    args = fixture(tmp_path)
    result = args[-1]
    decision = result["decisions"][0]
    if kind == "missing":
        result["decisions"] = []
    elif kind == "duplicate":
        result["decisions"].append(copy.deepcopy(decision))
    elif kind == "foreign":
        decision["candidate_id"] = "connection-ffffffffffffffff"
    elif kind == "quote":
        decision["evidence"][0]["quote"] = "invented evidence"
    elif kind == "one-sided":
        decision["evidence"].pop()
    elif kind == "scope":
        result["scope_sha256"] = "0" * 64
    elif kind == "fingerprint":
        result["candidates_sha256"] = "0" * 64
    else:
        result["component_inventory_fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(ExchangeError):
        review.promote(*args)


def test_review_implementation_evidence_is_retained_in_canonical_flow(tmp_path):
    args = fixture(tmp_path)
    args[-1]["decisions"][0]["evidence"].append(
        {
            "repository_id": args[0].repositories[0].repository_id,
            "file": "extra.py",
            "line": 1,
            "quote": "def enforce_identity(): return True",
        }
    )
    flows = review.promote(*args)[2]
    assert any(e["file"] == "extra.py" for e in flows["data_flows"][0]["evidence"])


def test_nested_authentication_cannot_borrow_upstream_repository_evidence(tmp_path):
    args = fixture(tmp_path)
    components, receipt, flows = review.promote(*args)
    flow = flows["data_flows"][0]
    sender = next(c for c in components["components"] if c["id"] == flow["from"])
    foreign = next(e for e in flow["evidence"] if e["repository_id"] in sender["repository_ids"])
    flow["authentication"] = {"scheme": "bearer", "scope": "Receiving interface", "evidence": [foreign]}
    with pytest.raises(AssessmentArchitectureError, match="receiving repository"):
        validate_flows(args[0], components, receipt, flows)
    foreign.pop("repository_id")
    with pytest.raises(AssessmentArchitectureError, match="schema"):
        validate_flows(args[0], components, receipt, flows)


def test_reviewer_retrieval_is_scoped_and_reuses_aggregate_budget(tmp_path):
    scope, documents, components, receipt, expected = fixture(tmp_path)

    class Host:
        def __init__(self):
            self.calls = 0

        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            self.calls += 1
            data = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
            if not data["source_slices"]:
                return HostReply(
                    {
                        "action": "read",
                        "artifact": None,
                        "reads": [
                            {"repository_id": r.repository_id, "path": "app.py", "start_line": 1, "end_line": 1}
                            for r in scope.repositories
                        ],
                    },
                    0.01,
                )
            return HostReply({"action": "complete", "reads": [], "artifact": expected}, 0.01)

    host = Host()
    budget = DiscoveryBudget(max_usd=0.10, call_usd=0.05, max_calls=4, timeout_s=60)
    result = review.review_connections(
        scope, documents, components, receipt, host_factory=lambda cap: host, budget=budget, should_stop=lambda: False
    )
    assert result == expected and host.calls == 2 and budget.spent_usd == pytest.approx(0.02)
