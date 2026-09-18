"""Finding attribution stays within the access each actor group can use."""

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from actor_attribution import reconcile_attribution  # noqa: E402
from actor_presentation import path_groups  # noqa: E402
from aggregate_run_issues import _extract_actor_model_corrections  # noqa: E402
from detect_open_registration import overview_actor_slug  # noqa: E402

ACTORS = [
    {"id": "ACT-D-01", "access": ["internet", "dmz"], "heatmap_slug": "internet-anon"},
    {"id": "ACT-D-02", "access": ["internet", "authenticated-user-session"], "heatmap_slug": "internet-user"},
    {"id": "ACT-D-04", "access": ["local-fs", "ci-cd-runtime", "internal-network"], "heatmap_slug": "insider"},
    {"id": "ACT-D-05", "access": ["prod-env", "prod-write-db", "deployment-pipeline"], "heatmap_slug": "insider"},
    {"id": "ACT-D-06", "access": ["build-pipeline", "ci-cd-runtime", "internet"], "heatmap_slug": "build-time"},
]


def components(app="orders-api", store="ledger-db", pipeline="release-ci"):
    return [
        {"id": app, "tier": "application", "deployment_zones": ["internet"]},
        {"id": store, "tier": "data", "deployment_zones": ["prod-write-db"]},
        {"id": pipeline, "tier": "application", "deployment_zones": ["ci-cd-runtime", "build-pipeline"]},
    ]


def finding(tid, component, cwe, file, actor_ids):
    return {
        "t_id": tid,
        "component_id": component,
        "cwe": cwe,
        "evidence": {"file": file, "line": 3},
        "actor_ids": list(actor_ids),
        "primary_actor": actor_ids[0] if actor_ids else None,
    }


def routes(repo, registration, handler_line=2):
    (repo / "server.js").write_text("const app = express()\n" + registration + "\n")
    return {
        "repo_root": str(repo),
        "routes": [
            {
                "route_id": "R-001",
                "path": "/items",
                "handler_file": "server.js",
                "handler_line": handler_line,
                "authn_signal": "middleware_present" if "requireLogin" in registration else "unknown",
            }
        ],
    }


@pytest.mark.parametrize(
    ("app", "file", "cwe"),
    [("orders-api", "lib/signing.ts", "CWE-321"), ("billing-svc", "billing/settings.py", "CWE-798")],
)
def test_supply_chain_attribution_leaves_a_committed_secret_on_an_application_component(app, file, cwe):
    threats = [finding("T-001", app, cwe, file, ["ACT-D-06", "ACT-D-01"])]
    corrections = reconcile_attribution(threats, components(app=app), ACTORS)
    assert threats[0]["actor_ids"] == ["ACT-D-01"]
    assert threats[0]["primary_actor"] == "ACT-D-01"
    assert corrections == [{"finding": "T-001", "removed": ["ACT-D-06"], "added": [], "actor_ids": ["ACT-D-01"]}]


@pytest.mark.parametrize(
    ("component", "cwe", "file"),
    [
        ("release-ci", "CWE-284", ".github/workflows/ci.yml"),
        ("orders-api", "CWE-1104", "src/vendor.ts"),
        ("orders-api", "CWE-20", "services/web/package.json"),
    ],
)
def test_build_time_attribution_stays_with_build_component_cwe_or_manifest_evidence(component, cwe, file):
    threats = [finding("T-001", component, cwe, file, ["ACT-D-06"])]
    assert reconcile_attribution(threats, components(), ACTORS) == []
    assert threats[0]["actor_ids"] == ["ACT-D-06"]


@pytest.mark.parametrize(
    ("handler", "registration", "expected"),
    [
        ("routes/productNotes.ts", "app.get('/items', productNotes())", "ACT-D-01"),
        ("handlers/invoice_export.js", "app.post('/items', requireLogin(), invoice_export())", "ACT-D-02"),
    ],
)
def test_insider_only_route_handler_finding_regains_an_internet_actor(tmp_path, handler, registration, expected):
    threats = [finding("T-004", "orders-api", "CWE-94", handler, ["ACT-D-05"])]
    corrections = reconcile_attribution(threats, components(), ACTORS, routes(tmp_path, registration))
    assert threats[0]["actor_ids"] == [expected]
    assert corrections[0]["removed"] == ["ACT-D-05"] and corrections[0]["added"] == [expected]


def test_route_rule_adds_an_internet_actor_beside_a_valid_insider(tmp_path):
    threats = [finding("T-002", "orders-api", "CWE-312", "routes/exportCards.ts", ["ACT-D-05"])]
    reconcile_attribution(threats, components(), ACTORS, routes(tmp_path, "app.get('/items', exportCards())"))
    assert threats[0]["actor_ids"] == ["ACT-D-05", "ACT-D-01"]


def test_at_rest_finding_on_a_data_store_stays_insider_only(tmp_path):
    threats = [finding("T-003", "ledger-db", "CWE-311", "models/index.ts", ["ACT-D-05"])]
    assert reconcile_attribution(threats, components(), ACTORS, routes(tmp_path, "app.get('/items', index())")) == []
    assert threats[0]["actor_ids"] == ["ACT-D-05"]


def test_unattributed_pipeline_finding_gains_the_build_time_actor_not_an_internet_one():
    threats = [finding("T-005", "release-ci", "CWE-1357", "Dockerfile", [])]
    corrections = reconcile_attribution(threats, components(), ACTORS)
    assert threats[0]["actor_ids"] == ["ACT-D-06"]
    assert corrections[0]["removed"] == [] and corrections[0]["added"] == ["ACT-D-06"]


def test_unknown_actors_stay_and_inactive_actors_are_never_the_fallback():
    threats = [finding("T-006", "orders-api", "CWE-400", "src/limits.ts", ["ACT-D-05", "ACT-X-9"])]
    reconcile_attribution(threats, components(), ACTORS)
    assert threats[0]["actor_ids"] == ["ACT-X-9"]
    actors = copy.deepcopy(ACTORS)
    actors[0]["_provenance"] = {"active": False}
    threats = [finding("T-007", "orders-api", "CWE-400", "src/limits.ts", ["ACT-D-05"])]
    reconcile_attribution(threats, components(), actors)
    assert threats[0]["actor_ids"] == ["ACT-D-02"]


def test_insider_reading_committed_content_projects_to_repository_read_but_keeps_its_own_group_otherwise():
    model = {
        "meta": {"public_source_repo": True},
        "actors": [{**a, "label": a["id"].lower(), "trust_positions": [], "active": True} for a in ACTORS],
        "threats": [
            {"id": "T-001", "vektor": "repo-read", "actor_ids": ["ACT-D-04"]},
            {"id": "T-002", "vektor": "internet-anon", "actor_ids": ["ACT-D-04"]},
        ],
    }
    groups = {g["actor"]: g["findings"] for g in path_groups(model, {"findings": ["T-001", "T-002"]})}
    assert groups == {"repo-read": ["T-001"], "insider": ["T-002"]}
    assert overview_actor_slug("repo-read", model["meta"]) == "internet-anon"
    assert overview_actor_slug("insider", model["meta"]) == "insider"


def test_merge_finalize_persists_schema_valid_corrections(tmp_path):
    from validate_intermediate import validate_threats_merged

    stride = {
        "component_id": "orders-api",
        "component_name": "Orders API",
        "threats": [
            {
                "title": "Hardcoded signing key",
                "cwe": "CWE-321",
                "stride": "Spoofing",
                "risk": "High",
                "likelihood": "High",
                "impact": "High",
                "evidence": {"file": "lib/signing.ts", "line": 3},
                "source": "stride",
                "architectural_violation": False,
                "actor_ids": ["ACT-D-06", "ACT-D-01"],
                "primary_actor": "ACT-D-06",
            }
        ],
    }
    (tmp_path / ".stride-orders-api.json").write_text(json.dumps(stride))
    (tmp_path / ".components.json").write_text(json.dumps({"components": components()}))
    (tmp_path / ".actors-resolved.json").write_text(json.dumps({"resolved_actors": ACTORS}))
    import merge_threats

    assert merge_threats.main(["collect", "--output-dir", str(tmp_path)]) == 0
    assert merge_threats.main(["finalize", "--output-dir", str(tmp_path)]) == 0
    merged = json.loads((tmp_path / ".threats-merged.json").read_text())
    assert merged["threats"][0]["actor_ids"] == ["ACT-D-01"]
    assert merged["actor_attribution_corrections"][0]["removed"] == ["ACT-D-06"]
    assert validate_threats_merged(merged, tmp_path)[0], validate_threats_merged(merged, tmp_path)[1]
    issues = _extract_actor_model_corrections(tmp_path, [])
    assert [i["category"] for i in issues] == ["actor_attribution_corrected"]


def test_fills_alone_are_no_run_issue_but_a_privileged_role_event_is(tmp_path):
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"actor_attribution_corrections": [{"finding": "T-001", "removed": [], "added": ["ACT-D-06"]}]})
    )
    from event_log import format_line

    line = format_line(
        "PRIVILEGED_ROLE_ADDED", "actor=ACT-D-03 entity=ext-a", level="WARN", component="skill-controller"
    )
    issues = _extract_actor_model_corrections(tmp_path, [(7, line.rstrip("\n"))])
    assert [(i["category"], i["evidence"]["log_line"]) for i in issues] == [("privileged_role_added", 7)]
