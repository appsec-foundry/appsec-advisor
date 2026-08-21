from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import build_stride_evidence_bundles as bundles
import pytest


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    source = repo / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("def login(user):\n    return user\n", encoding="utf-8")
    _git(repo, "add", "src/app.py")
    _git(repo, "commit", "-m", "fixture")
    output = repo / "docs" / "security"
    output.mkdir(parents=True)
    return repo, output


def _component(**overrides) -> dict:
    component = {
        "component_id": "backend-api",
        "component_name": "Backend API",
        "component_description": "Handles login requests.",
        "component_paths": ["src/**"],
        "component_complexity": "moderate",
        "max_turns": 22,
        "interfaces": ["POST /login"],
        "controls": ["Session cookie"],
        "index_paths": {
            "prior_findings": "none",
            "known_threats": "none",
            "cross_repo": "none",
            "requirements_violations": "none",
            "relevant_actors": "none",
            "trust_boundaries": "none",
        },
    }
    component.update(overrides)
    return component


def _manifest(*components: dict) -> dict:
    return {"schema_version": 1, "components": list(components) or [_component()]}


def _write_signal(output: Path, **overrides) -> None:
    finding = {"file": "src/app.py", "line": 1, "rule_id": "AUTH-1"}
    finding.update(overrides)
    (output / ".source-auth-findings.json").write_text(
        json.dumps({"findings": [finding]}),
        encoding="utf-8",
    )


def test_build_all_emits_bounded_valid_component_bundle(tmp_path):
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = bundles.build_all(output, repo, _manifest())

    component = manifest["components"][0]
    assert manifest["context_version"] == 2
    assert component["evidence_bundle_path"] == ".dispatch-context/backend-api/evidence-bundle.json"
    bundle_path = output / component["evidence_bundle_path"]
    payload = bundle_path.read_bytes()
    assert component["evidence_bundle_sha256"] == hashlib.sha256(payload).hexdigest()

    parsed = bundles.validate_bundle(
        bundle_path,
        {"primary": repo},
        expected_component_id="backend-api",
        expected_sha256=component["evidence_bundle_sha256"],
        output_dir=output,
    )
    assert parsed["limits"]["serialized_bytes"] == len(payload)
    assert parsed["limits"]["estimated_tokens"] <= bundles.MAX_ESTIMATED_TOKENS
    assert parsed["source_slices"][0]["path"] == "src/app.py"
    assert parsed["evidence"]["interfaces"][0]["value"] == "POST /login"
    assert "business_context" not in parsed
    assert "business_context_path" not in component
    assert not (output / ".dispatch-context/backend-api/business-context.json").exists()
    assert "architecture_context" not in parsed
    assert "architecture_context_path" not in component
    assert not (output / ".dispatch-context/backend-api/architecture-context.json").exists()


def test_build_all_reconstructs_its_canonical_empty_routing_lists(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = _manifest(_component())

    first = bundles.build_all(output, repo, manifest)
    first_payload = (output / first["components"][0]["evidence_bundle_path"]).read_bytes()
    second = bundles.build_all(output, repo, first)
    second_payload = (output / second["components"][0]["evidence_bundle_path"]).read_bytes()

    assert second["components"][0]["focus_paths"] == []
    assert second["components"][0]["exclude_paths"] == []
    assert second_payload == first_payload


def test_build_all_keeps_its_context_sources_so_a_second_build_repeats_itself(tmp_path):
    repo, output = _repo(tmp_path)
    business = {"business_purpose": "Authorize customer payments."}
    architecture = {"security_role": "Validate and route authenticated API requests."}
    manifest = _manifest(_component(business_context=business, architecture_context=architecture))

    first = bundles.build_all(output, repo, manifest)
    business_payload = (output / ".dispatch-context/backend-api/business-context.json").read_bytes()
    architecture_payload = (output / ".dispatch-context/backend-api/architecture-context.json").read_bytes()
    second = bundles.build_all(output, repo, first)

    assert second == first
    assert (output / ".dispatch-context/backend-api/business-context.json").read_bytes() == business_payload
    assert (output / ".dispatch-context/backend-api/architecture-context.json").read_bytes() == architecture_payload


def test_business_context_is_normalized_and_receipted_per_component(tmp_path):
    repo, output = _repo(tmp_path)
    context = {
        "business_purpose": "  Authorize customer payments.  ",
        "impact_if_compromised": "Unauthorized transfers and delayed settlement.",
        "sensitive_assets": [" Payment instructions ", "Account identifiers", "Account identifiers"],
        "security_obligations": ["PCI DSS scope"],
        "security_assumptions": ["The upstream identity provider authenticates workforce users."],
    }
    manifest = bundles.build_all(output, repo, _manifest(_component(business_context=context)))
    component = manifest["components"][0]
    assert component["business_context_path"] == ".dispatch-context/backend-api/business-context.json"
    projection_path = output / component["business_context_path"]
    projection = bundles.validate_business_context_bytes(
        projection_path.read_bytes(),
        expected_component_id="backend-api",
        expected_sha256=component["business_context_sha256"],
    )
    assert projection["attributes"]["business_purpose"] == "Authorize customer payments."
    assert projection["attributes"]["sensitive_assets"] == ["Payment instructions", "Account identifiers"]
    assert (
        projection["source_content_sha256"]
        == hashlib.sha256(bundles._canonical_bytes(projection["attributes"])).hexdigest()
    )
    assert component["business_context"] == context
    bundle = json.loads((output / component["evidence_bundle_path"]).read_text())
    assert "business_context" not in bundle


@pytest.mark.parametrize(
    ("business_context", "message"),
    [
        ({"criticality_weight": 9}, "unknown attributes"),
        ({"business_purpose": "   "}, "empty or oversized"),
        ({"sensitive_assets": []}, "must contain 1-8 items"),
        ({"security_obligations": [f"obligation-{index}" for index in range(9)]}, "must contain 1-8 items"),
    ],
)
def test_business_context_rejects_technical_unknown_empty_and_oversized_values(tmp_path, business_context, message):
    repo, output = _repo(tmp_path)
    with pytest.raises(bundles.BundleError, match=message):
        bundles.build_all(output, repo, _manifest(_component(business_context=business_context)))


def test_bundle_rejects_tampered_business_context_receipt(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(
        output,
        repo,
        _manifest(_component(business_context={"business_purpose": "Process orders."})),
    )
    path = output / manifest["components"][0]["business_context_path"]
    projection = json.loads(path.read_text(encoding="utf-8"))
    projection["attributes"]["business_purpose"] = "Changed after admission."
    payload = bundles._canonical_bytes(projection) + b"\n"

    with pytest.raises(bundles.BundleError, match="source fingerprint is stale"):
        bundles.validate_business_context_bytes(payload, expected_component_id="backend-api")


def test_business_context_is_physically_omitted_for_unrelated_component(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(
        output,
        repo,
        _manifest(
            _component(business_context={"business_purpose": "Serve customers."}),
            _component(component_id="internal-worker", component_name="Internal worker"),
        ),
    )
    by_id = {row["component_id"]: row for row in manifest["components"]}
    assert "business_context_path" in by_id["backend-api"]
    assert "business_context_path" not in by_id["internal-worker"]
    assert not (output / ".dispatch-context/internal-worker/business-context.json").exists()


def test_architecture_context_is_normalized_and_receipted_per_component(tmp_path):
    repo, output = _repo(tmp_path)
    context = {
        "security_role": "  Validate and route authenticated API requests.  ",
        "exposed_interfaces": [" HTTPS API ", "HTTPS API", "Internal event consumer"],
        "security_dependencies": ["Identity provider", "Payment service"],
        "deployment_constraints": ["Runs behind the public ingress"],
        "architecture_assumptions": ["The ingress preserves the authenticated principal."],
    }
    manifest = bundles.build_all(output, repo, _manifest(_component(architecture_context=context)))
    component = manifest["components"][0]
    assert component["architecture_context_path"] == ".dispatch-context/backend-api/architecture-context.json"
    projection_path = output / component["architecture_context_path"]
    projection = bundles.validate_architecture_context_bytes(
        projection_path.read_bytes(),
        expected_component_id="backend-api",
        expected_sha256=component["architecture_context_sha256"],
    )
    assert projection["attributes"]["security_role"] == "Validate and route authenticated API requests."
    assert projection["attributes"]["exposed_interfaces"] == ["HTTPS API", "Internal event consumer"]
    assert component["architecture_context"] == context
    bundle = json.loads((output / component["evidence_bundle_path"]).read_text())
    assert "architecture_context" not in bundle


@pytest.mark.parametrize(
    ("architecture_context", "message"),
    [
        ({"trust_boundaries": ["internet"]}, "unknown attributes"),
        ({"security_role": "   "}, "empty or oversized"),
        ({"exposed_interfaces": []}, "must contain 1-8 items"),
        ({"architecture_assumptions": [f"assumption-{index}" for index in range(9)]}, "must contain 1-8 items"),
    ],
)
def test_architecture_context_rejects_other_categories_empty_and_oversized_values(
    tmp_path, architecture_context, message
):
    repo, output = _repo(tmp_path)
    with pytest.raises(bundles.BundleError, match=message):
        bundles.build_all(output, repo, _manifest(_component(architecture_context=architecture_context)))


def test_architecture_context_is_physically_omitted_for_unrelated_component(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(
        output,
        repo,
        _manifest(
            _component(architecture_context={"security_role": "Public API ingress."}),
            _component(component_id="internal-worker", component_name="Internal worker"),
        ),
    )
    by_id = {row["component_id"]: row for row in manifest["components"]}
    assert "architecture_context_path" in by_id["backend-api"]
    assert "architecture_context_path" not in by_id["internal-worker"]
    assert not (output / ".dispatch-context/internal-worker/architecture-context.json").exists()


def test_bundle_rejects_tampered_architecture_context_receipt(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(
        output,
        repo,
        _manifest(_component(architecture_context={"security_role": "Route public API requests."})),
    )
    path = output / manifest["components"][0]["architecture_context_path"]
    projection = json.loads(path.read_text(encoding="utf-8"))
    projection["attributes"]["security_role"] = "Changed after admission."
    payload = bundles._canonical_bytes(projection) + b"\n"

    with pytest.raises(bundles.BundleError, match="source fingerprint is stale"):
        bundles.validate_architecture_context_bytes(payload, expected_component_id="backend-api")


def test_security_categories_are_independent_receipted_component_projections(tmp_path):
    repo, output = _repo(tmp_path)
    context_dir = output / ".dispatch-context" / "backend-api"
    context_dir.mkdir(parents=True)
    sources = {
        "known_threats": ("known-threats.json", [{"id": "KT-1", "status": "open"}]),
        "prior_findings": ("prior-findings.json", [{"id": "F-017", "status": "open"}]),
        "relevant_actors": ("actors.json", {"actors": [{"id": "actor-customer"}]}),
        "trust_boundaries": ("trust-boundaries.json", {"trust_boundaries": [{"id": "tb-1"}]}),
        "requirements_violations": ("requirements.json", {"violations": [{"id": "REQ-1"}]}),
    }
    component = _component(controls=["Session cookie", "Authorization middleware"])
    for index_name, (filename, document) in sources.items():
        path = context_dir / filename
        path.write_text(json.dumps(document), encoding="utf-8")
        component["index_paths"][index_name] = path.relative_to(output).as_posix()

    manifest = bundles.build_all(output, repo, _manifest(component))
    built = manifest["components"][0]
    by_id = {row["context_id"]: row for row in built["security_context_projections"]}
    assert set(by_id) == {
        "actors.component_context",
        "controls.component_context",
        "prior_run.component_findings",
        "requirements.component_context",
        "threats.known_threats",
        "trust_boundaries.component_context",
    }
    for context_id, row in by_id.items():
        payload = (output / row["artifact_path"]).read_bytes()
        projection = bundles.validate_security_context_bytes(
            payload,
            expected_component_id="backend-api",
            expected_context_id=context_id,
            expected_sha256=row["sha256"],
        )
        assert projection["records"]
        assert projection["limits"]["retained_count"] == len(projection["records"])
        assert projection["limits"]["estimated_tokens"] == row["estimated_tokens"]

    bundle = json.loads((output / built["evidence_bundle_path"]).read_text(encoding="utf-8"))
    assert set(bundle["evidence"]) == {"interfaces", "cross_repo", "recon_signals"}


def test_known_threat_projection_preserves_one_record_per_catalog_threat(tmp_path):
    repo, output = _repo(tmp_path)
    context_dir = output / ".dispatch-context" / "backend-api"
    context_dir.mkdir(parents=True)
    source = context_dir / "known-threats.json"
    source.write_text(
        json.dumps({"threats": [{"id": "KT-1"}, {"id": "KT-2"}], "schema_version": 1}),
        encoding="utf-8",
    )
    component = _component()
    component["index_paths"]["known_threats"] = source.relative_to(output).as_posix()

    manifest = bundles.build_all(output, repo, _manifest(component))
    row = manifest["components"][0]["security_context_projections"][0]
    projection = json.loads((output / row["artifact_path"]).read_text(encoding="utf-8"))

    assert projection["context_id"] == "threats.known_threats"
    assert projection["limits"]["original_count"] == 2
    assert {json.loads(record["value"])["id"] for record in projection["records"]} == {"KT-1", "KT-2"}


def test_analyst_known_vulnerabilities_are_receipted_as_known_threats(tmp_path):
    repo, output = _repo(tmp_path)
    component = _component(known_vulns=["src/app.py:1 — login trusts an unverified identity claim"])

    manifest = bundles.build_all(output, repo, _manifest(component))
    row = next(
        item
        for item in manifest["components"][0]["security_context_projections"]
        if item["context_id"] == "threats.known_threats"
    )
    projection = json.loads((output / row["artifact_path"]).read_text(encoding="utf-8"))

    assert projection["source"]["kind"] == "component_manifest"
    assert projection["source"]["manifest_field"] == "known_vulns"
    assert [record["value"] for record in projection["records"]] == [
        "src/app.py:1 — login trusts an unverified identity claim"
    ]


def test_team_and_analyst_known_threats_share_one_receipted_route(tmp_path):
    repo, output = _repo(tmp_path)
    context_dir = output / ".dispatch-context" / "backend-api"
    context_dir.mkdir(parents=True)
    source = context_dir / "known-threats.json"
    source.write_text(json.dumps({"threats": [{"id": "KT-1"}]}), encoding="utf-8")
    component = _component(known_vulns=["src/app.py:1 — analyst candidate"])
    component["index_paths"]["known_threats"] = source.relative_to(output).as_posix()

    manifest = bundles.build_all(output, repo, _manifest(component))
    rows = [
        item
        for item in manifest["components"][0]["security_context_projections"]
        if item["context_id"] == "threats.known_threats"
    ]
    projection = json.loads((output / rows[0]["artifact_path"]).read_text(encoding="utf-8"))

    assert len(rows) == 1
    assert projection["source"]["kind"] == "component_index_and_manifest"
    assert projection["limits"]["original_count"] == 2


def test_empty_security_category_is_physically_omitted_and_removes_stale_projection(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(controls=["Session cookie"])))
    component = manifest["components"][0]
    assert {row["context_id"] for row in component["security_context_projections"]} == {"controls.component_context"}

    rebuilt = bundles.build_all(output, repo, _manifest(_component(controls=[])))
    component = rebuilt["components"][0]
    assert "security_context_projections" not in component
    assert not (output / ".dispatch-context/backend-api/controls-context.json").exists()


def test_bundle_builder_rejects_symlinked_dispatch_directory(tmp_path):
    repo, output = _repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (output / ".dispatch-context").symlink_to(outside, target_is_directory=True)

    with pytest.raises(bundles.BundleError, match="path escapes registered repository root"):
        bundles.build_all(output, repo, _manifest())

    assert list(outside.iterdir()) == []


def test_security_context_projection_rejects_tampered_record_fingerprint(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(controls=["Session cookie"])))
    row = manifest["components"][0]["security_context_projections"][0]
    path = output / row["artifact_path"]
    projection = json.loads(path.read_text(encoding="utf-8"))
    projection["records"][0]["value"] = "Session token!"
    payload = bundles._canonical_bytes(projection) + b"\n"

    with pytest.raises(bundles.BundleError, match="record fingerprint is stale"):
        bundles.validate_security_context_bytes(payload, expected_component_id="backend-api")


def test_security_context_schema_binds_route_to_source_kind(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(controls=["Session cookie"])))
    row = manifest["components"][0]["security_context_projections"][0]
    projection = json.loads((output / row["artifact_path"]).read_text(encoding="utf-8"))
    projection["source"] = {
        "kind": "component_index",
        "artifact_path": ".controls.json",
        "artifact_sha256": "0" * 64,
        "content_sha256": projection["source"]["content_sha256"],
    }

    with pytest.raises(bundles.BundleError, match="schema validation failed"):
        bundles.validate_security_context_bytes(bundles._canonical_bytes(projection) + b"\n")


def test_split_security_contexts_retain_the_former_aggregate_budget(tmp_path):
    repo, output = _repo(tmp_path)
    context_dir = output / ".dispatch-context" / "backend-api"
    context_dir.mkdir(parents=True)
    component = _component(controls=[f"control-{index}-" + "x" * 4000 for index in range(32)])
    for index_name, filename in (
        ("known_threats", "known-threats.json"),
        ("prior_findings", "prior-findings.json"),
        ("relevant_actors", "actors.json"),
        ("trust_boundaries", "boundaries.json"),
        ("requirements_violations", "requirements.json"),
    ):
        path = context_dir / filename
        path.write_text(json.dumps([f"{index_name}-{index}-" + "y" * 4000 for index in range(32)]), encoding="utf-8")
        component["index_paths"][index_name] = path.relative_to(output).as_posix()

    manifest = bundles.build_all(output, repo, _manifest(component))
    rows = manifest["components"][0]["security_context_projections"]
    payloads = [(output / row["artifact_path"]).read_bytes() for row in rows]
    projections = [json.loads(payload) for payload in payloads]

    assert sum(len(payload) for payload in payloads) <= bundles.MAX_BUNDLE_BYTES
    assert sum(value["limits"]["estimated_tokens"] for value in projections) <= bundles.MAX_ESTIMATED_TOKENS
    assert sum(value["limits"]["omitted_count"] for value in projections) > 0


def test_focus_path_is_normalized_and_changes_bounded_admission(tmp_path):
    repo, output = _repo(tmp_path)
    focused = repo / "src" / "priority.py"
    focused.write_text("def priority():\n    return True\n", encoding="utf-8")

    baseline = bundles.build_all(output, repo, _manifest(_component()))
    baseline_bundle = json.loads((output / baseline["components"][0]["evidence_bundle_path"]).read_text())
    assert baseline_bundle["source_slices"] == []

    manifest = bundles.build_all(
        output,
        repo,
        _manifest(_component(focus_paths="  src/priority.py  ")),
    )
    component = manifest["components"][0]
    bundle = json.loads((output / component["evidence_bundle_path"]).read_text())

    assert component["focus_paths"] == ["src/priority.py"]
    assert component["exclude_paths"] == []
    assert bundle["source_slices"][0]["path"] == "src/priority.py"
    assert bundle["source_slices"][0]["signal_kind"] == "focus-path"
    assert bundle["path_routing"]["focus_admission"] == [
        {
            "path": "src/priority.py",
            "status": "admitted",
            "reason": "projected",
            "candidate_files": 1,
            "projected_files": ["src/priority.py"],
            "omitted_files": 0,
            "unowned_files": 0,
            "enumeration_truncated": False,
        }
    ]


def test_focus_directory_matches_component_glob_with_file_suffix(tmp_path):
    repo, output = _repo(tmp_path)
    routes = repo / "routes"
    routes.mkdir()
    (routes / "login.ts").write_text("export const login = true\n", encoding="utf-8")

    component = _component(component_paths=["routes/**/*.ts"], focus_paths=["routes"])
    manifest = bundles.build_all(output, repo, _manifest(component))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())

    assert manifest["components"][0]["focus_paths"] == ["routes"]
    assert bundle["source_slices"][0]["path"] == "routes/login.ts"
    assert bundle["path_routing"]["focus_admission"][0]["status"] == "admitted"
    bundles.validate_bundle(
        output / manifest["components"][0]["evidence_bundle_path"],
        {"primary": repo},
        expected_component_id="backend-api",
        expected_sha256=manifest["components"][0]["evidence_bundle_sha256"],
        output_dir=output,
        expected_focus_paths=["routes"],
        expected_exclude_paths=[],
    )


def test_focus_directory_drops_files_the_component_glob_does_not_own(tmp_path):
    """A typed component glob plus any non-matching file in the focus directory.

    ``src/api`` is admitted through the literal prefix of ``src/api/**/*.py``,
    so the enumeration legitimately reaches a README the pattern never owns.
    The unowned file is dropped from the projection and receipted; it must not
    abort the run, and it must not reach the bundle either. It is also not an
    omission: the component owns one file here and that file was projected, so
    the receipt reads ``projected`` and discloses the foreign file separately.
    """
    repo, output = _repo(tmp_path)
    api = repo / "src" / "api"
    api.mkdir()
    (api / "handler.py").write_text("handler = True\n", encoding="utf-8")
    (api / "README.md").write_text("# api\n", encoding="utf-8")

    component = _component(component_paths=["src/api/**/*.py"], focus_paths=["src/api"])
    manifest = bundles.build_all(output, repo, _manifest(component))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    receipt = bundle["path_routing"]["focus_admission"][0]

    assert receipt["projected_files"] == ["src/api/handler.py"]
    assert receipt["unowned_files"] == 1
    assert receipt["omitted_files"] == 0
    assert receipt["candidate_files"] == 2
    assert receipt["reason"] == "projected"
    assert "src/api/README.md" not in {row["path"] for row in bundle["source_slices"]}
    bundles.validate_bundle(
        output / manifest["components"][0]["evidence_bundle_path"],
        {"primary": repo},
        expected_component_id="backend-api",
        expected_sha256=manifest["components"][0]["evidence_bundle_sha256"],
        output_dir=output,
        expected_focus_paths=["src/api"],
        expected_exclude_paths=[],
    )


def test_non_recursive_component_glob_excludes_nested_focus_files(tmp_path):
    """``pkg/*.py`` owns no subdirectory, so ``pkg/sub/deep.py`` stays out."""
    repo, output = _repo(tmp_path)
    pkg = repo / "src" / "pkg"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "top.py").write_text("top = 1\n", encoding="utf-8")
    (pkg / "sub" / "deep.py").write_text("deep = 1\n", encoding="utf-8")

    component = _component(component_paths=["src/pkg/*.py"], focus_paths=["src/pkg"])
    manifest = bundles.build_all(output, repo, _manifest(component))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())

    assert bundle["path_routing"]["focus_admission"][0]["projected_files"] == ["src/pkg/top.py"]
    assert bundle["path_routing"]["focus_admission"][0]["unowned_files"] == 1
    assert all(row["path"] != "src/pkg/sub/deep.py" for row in bundle["source_slices"])


def test_focus_directory_holding_only_unowned_files_is_receipted_not_fatal(tmp_path):
    """Every enumerated file unowned: the focus path is omitted, the run lives."""
    repo, output = _repo(tmp_path)
    pkg = repo / "src" / "pkg"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "sub" / "deep.py").write_text("deep = 1\n", encoding="utf-8")

    component = _component(component_paths=["src/pkg/*.py"], focus_paths=["src/pkg"])
    manifest = bundles.build_all(output, repo, _manifest(component))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    receipt = bundle["path_routing"]["focus_admission"][0]

    assert receipt["status"] == "omitted"
    assert receipt["reason"] == "outside-component"
    assert receipt["projected_files"] == []
    assert receipt["unowned_files"] == 1
    bundles.validate_bundle(
        output / manifest["components"][0]["evidence_bundle_path"],
        {"primary": repo},
        expected_component_id="backend-api",
        expected_sha256=manifest["components"][0]["evidence_bundle_sha256"],
        output_dir=output,
        expected_focus_paths=["src/pkg"],
        expected_exclude_paths=[],
    )


def test_focus_admission_reason_ladder_is_shared_by_builder_and_validator(tmp_path):
    """The validator must recompute the builder's reason from the receipt alone.

    Builder and validator drifting apart on the same predicate is the defect
    class this guards: a receipt the builder can emit but the validator cannot
    reproduce fails the second pass and aborts a completed run.
    """
    repo, output = _repo(tmp_path)
    api = repo / "src" / "api"
    api.mkdir()
    (api / "handler.py").write_text("handler = True\n", encoding="utf-8")
    (api / "README.md").write_text("# api\n", encoding="utf-8")

    manifest = bundles.build_all(
        output, repo, _manifest(_component(component_paths=["src/api/**/*.py"], focus_paths=["src/api"]))
    )
    bundle_path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(bundle_path.read_text())

    for receipt in bundle["path_routing"]["focus_admission"]:
        assert receipt["reason"] == bundles._focus_admission_reason(
            projected=bool(receipt["projected_files"]),
            omitted=receipt["omitted_files"],
            enumeration_truncated=receipt["enumeration_truncated"],
            owned_candidates=receipt["candidate_files"] - receipt["unowned_files"],
            unowned_files=receipt["unowned_files"],
        )


def test_exclude_without_evidence_collision_is_still_applied(tmp_path):
    """Superseding must be narrow: an exclude that hides nothing cited still bites."""
    repo, output = _repo(tmp_path)
    _write_signal(output, file="src/app.py", line=1)
    legacy = repo / "src" / "legacy"
    legacy.mkdir()
    (legacy / "old.py").write_text("old = 1\n", encoding="utf-8")

    component = _component(component_paths=["src/**"], exclude_paths=["src/legacy"])
    manifest = bundles.build_all(output, repo, _manifest(component))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())

    assert bundle["path_routing"]["exclude_paths"] == ["src/legacy"]
    assert bundle["path_routing"]["exclude_application"][0]["status"] == "applied"
    assert bundle["path_routing"]["exclude_application"][0]["superseded_by"] == []
    assert all(not row["path"].startswith("src/legacy") for row in bundle["source_slices"])


def test_routing_defect_degrades_one_component_instead_of_the_run(tmp_path, monkeypatch):
    """Routing hints are prioritization, not evidence: they may never kill a run.

    build_all walks every component in one pass, so without containment a single
    component's routing defect discards a Stage 1 that many agents already
    finished.
    """
    repo, output = _repo(tmp_path)
    real_build_bundle = bundles.build_bundle

    def flaky(output_dir, component, registry, **kwargs):
        if component.get("focus_paths") or component.get("exclude_paths"):
            raise bundles.RoutingHintError("synthetic routing defect")
        return real_build_bundle(output_dir, component, registry, **kwargs)

    monkeypatch.setattr(bundles, "build_bundle", flaky)
    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    entry = manifest["components"][0]
    bundle = json.loads((output / entry["evidence_bundle_path"]).read_text())

    # the manifest records what was asked for; the bundle records what took effect
    assert entry["focus_paths"] == ["src/app.py"]
    assert bundle["path_routing"]["focus_paths"] == []
    # the drop must survive in the artifact, not only on stderr: a degraded
    # bundle would otherwise be indistinguishable from one that never had routing
    assert bundle["path_routing"]["degraded"] == {
        "reason": "routing-hints-dropped",
        "error": "synthetic routing defect",
        "dropped_focus_paths": ["src/app.py"],
        "dropped_exclude_paths": [],
    }
    bundles.validate_bundle(
        output / entry["evidence_bundle_path"],
        {"primary": repo},
        expected_component_id="backend-api",
        expected_sha256=entry["evidence_bundle_sha256"],
        output_dir=output,
        expected_focus_paths=["src/app.py"],
        expected_exclude_paths=[],
    )


def test_undegraded_bundle_carries_no_degraded_marker(tmp_path):
    """The marker has to mean something: a normal build never sets it."""
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())

    assert "degraded" not in bundle["path_routing"]
    assert bundle["path_routing"]["focus_paths"] == ["src/app.py"]


def test_containment_does_not_mask_a_failure_unrelated_to_routing(tmp_path, monkeypatch):
    """Without routing hints to drop there is nothing to degrade — raise as before."""
    repo, output = _repo(tmp_path)

    def always_fails(output_dir, component, registry):
        raise bundles.BundleError("genuine contract violation")

    monkeypatch.setattr(bundles, "build_bundle", always_fails)
    with pytest.raises(bundles.BundleError, match="genuine contract violation"):
        bundles.build_all(output, repo, _manifest(_component()))


def test_containment_retries_once_and_then_propagates(tmp_path, monkeypatch):
    """A defect that survives dropping the hints must surface, not loop."""
    repo, output = _repo(tmp_path)
    attempts = []

    def persistent(output_dir, component, registry, **kwargs):
        attempts.append(component.get("focus_paths"))
        raise bundles.RoutingHintError("persistent defect")

    monkeypatch.setattr(bundles, "build_bundle", persistent)
    with pytest.raises(bundles.BundleError, match="persistent defect"):
        bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    assert len(attempts) == 2


def test_containment_does_not_retry_a_failure_outside_routing(tmp_path, monkeypatch):
    """Only RoutingHintError is contained; every other BundleError stays fatal.

    Retrying any BundleError without the hints made "it builds without routing"
    the proof that routing was at fault, which it is not. A producer defect that
    merely happens to disappear with the hints was silently downgraded to a
    degraded bundle and the run continued on data the validator had rejected.
    """
    repo, output = _repo(tmp_path)
    attempts = []

    def unrelated_defect(output_dir, component, registry, **kwargs):
        attempts.append(component.get("focus_paths"))
        raise bundles.BundleError("evidence bundle schema validation failed")

    monkeypatch.setattr(bundles, "build_bundle", unrelated_defect)
    with pytest.raises(bundles.BundleError, match="schema validation failed"):
        bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    assert attempts == [["src/app.py"]]


def test_unreadable_file_under_a_focus_path_degrades_instead_of_aborting(tmp_path):
    """The one condition the containment exists for, raised where it happens."""
    repo, output = _repo(tmp_path)
    api = repo / "src" / "api"
    api.mkdir()
    unreadable = api / "handler.py"
    unreadable.write_text("handler = True\n", encoding="utf-8")
    unreadable.chmod(0o000)
    if os.access(unreadable, os.R_OK):  # running as root — the mode cannot bite
        pytest.skip("cannot make a file unreadable for this user")

    try:
        manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/api"])))
    finally:
        unreadable.chmod(0o644)
    entry = manifest["components"][0]
    bundle = json.loads((output / entry["evidence_bundle_path"]).read_text())

    assert bundle["path_routing"]["degraded"]["dropped_focus_paths"] == ["src/api"]
    assert entry["focus_paths"] == ["src/api"]


def test_escaping_symlink_in_a_focus_directory_is_skipped_not_fatal(tmp_path):
    """The enumeration promises not to follow an escaping link, so it may not raise."""
    repo, output = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("value = 1\n", encoding="utf-8")
    api = repo / "src" / "api"
    api.mkdir()
    (api / "handler.py").write_text("handler = True\n", encoding="utf-8")
    os.symlink(outside, api / "linked.py")

    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/api"])))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    receipt = bundle["path_routing"]["focus_admission"][0]

    assert receipt["projected_files"] == ["src/api/handler.py"]
    assert receipt["candidate_files"] == 1
    assert "degraded" not in bundle["path_routing"]


def test_glob_metacharacters_in_a_discovered_path_do_not_break_the_bundle(tmp_path):
    """A dynamic-route filename is a legal repository path, not a routing pattern.

    Typing the discovered paths of the receipt like the literal routing inputs
    rejected every ``app/[slug]/page.tsx`` a scan reaches, which cost the whole
    component its routing on any framework that names files this way.
    """
    repo, output = _repo(tmp_path)
    api = repo / "src" / "api"
    api.mkdir()
    (api / "[slug].py").write_text("route = True\n", encoding="utf-8")
    _write_signal(output, file="src/api/[slug].py")

    # one component reaches the file through a focus path, the other has it
    # superseded out of an exclude — the two receipt fields that hold it
    manifest = bundles.build_all(
        output,
        repo,
        _manifest(
            _component(focus_paths=["src/api"]),
            _component(component_id="worker", exclude_paths=["src/api"]),
        ),
    )
    focused, excluded = (
        json.loads((output / entry["evidence_bundle_path"]).read_text()) for entry in manifest["components"]
    )

    assert "degraded" not in focused["path_routing"]
    assert "degraded" not in excluded["path_routing"]
    assert focused["path_routing"]["focus_admission"][0]["projected_files"] == ["src/api/[slug].py"]
    assert excluded["path_routing"]["exclude_application"][0]["superseded_by"] == ["src/api/[slug].py"]
    for entry in manifest["components"]:
        bundles.validate_bundle(
            output / entry["evidence_bundle_path"],
            {"primary": repo},
            expected_component_id=entry["component_id"],
            expected_sha256=entry["evidence_bundle_sha256"],
            output_dir=output,
            expected_focus_paths=entry["focus_paths"],
            expected_exclude_paths=entry["exclude_paths"],
        )


def test_second_build_repeats_itself_when_an_exclude_was_superseded(tmp_path):
    """Supersession depends on the scanner artifacts, not on the manifest input.

    Writing the effective set back over the request dropped the superseded row
    from the receipt on the next build, so the boundary answered the same
    manifest with different bytes.
    """
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = _manifest(_component(exclude_paths=["src/app.py"]))

    first = bundles.build_all(output, repo, manifest)
    first_payload = (output / first["components"][0]["evidence_bundle_path"]).read_bytes()
    second = bundles.build_all(output, repo, first)
    second_payload = (output / second["components"][0]["evidence_bundle_path"]).read_bytes()

    assert second_payload == first_payload
    assert second["components"][0]["exclude_paths"] == ["src/app.py"]


def test_second_build_repeats_itself_after_routing_was_dropped(tmp_path, monkeypatch):
    """A degraded bundle must stay degraded when its own manifest is rebuilt."""
    repo, output = _repo(tmp_path)
    real_build_bundle = bundles.build_bundle

    def flaky(output_dir, component, registry, **kwargs):
        if component.get("focus_paths"):
            raise bundles.RoutingHintError("synthetic routing defect")
        return real_build_bundle(output_dir, component, registry, **kwargs)

    monkeypatch.setattr(bundles, "build_bundle", flaky)
    first = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    first_payload = (output / first["components"][0]["evidence_bundle_path"]).read_bytes()
    second = bundles.build_all(output, repo, first)
    second_payload = (output / second["components"][0]["evidence_bundle_path"]).read_bytes()

    assert second_payload == first_payload
    assert json.loads(second_payload)["path_routing"]["degraded"]["dropped_focus_paths"] == ["src/app.py"]


def test_focus_directory_above_component_glob_prefix_is_rejected(tmp_path):
    repo, output = _repo(tmp_path)
    api = repo / "src" / "api"
    api.mkdir()
    (api / "login.py").write_text("login = True\n", encoding="utf-8")

    component = _component(component_paths=["src/api/**/*.py"], focus_paths=["src"])
    with pytest.raises(bundles.BundleError, match="outside the component paths"):
        bundles.build_all(output, repo, _manifest(component))


def test_focus_receipt_discloses_source_budget_omissions(tmp_path):
    repo, output = _repo(tmp_path)
    for index in range(bundles.MAX_SOURCE_SLICES + 2):
        (repo / "src" / f"file-{index:02d}.py").write_text("value = 1\n", encoding="utf-8")

    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src"])))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    receipt = bundle["path_routing"]["focus_admission"][0]

    assert len(bundle["source_slices"]) == bundles.MAX_SOURCE_SLICES
    assert receipt["status"] == "admitted"
    assert receipt["reason"] == "partially-projected"
    assert receipt["candidate_files"] == bundles.MAX_SOURCE_SLICES + 3
    assert len(receipt["projected_files"]) == bundles.MAX_SOURCE_SLICES
    assert receipt["omitted_files"] == 3


def test_later_focus_mechanism_cannot_be_starved_by_lexical_signal_fanout(tmp_path):
    repo, output = _repo(tmp_path)
    early = repo / "src" / "a-common.py"
    early.write_text("\n".join(f"value_{index} = {index}" for index in range(40)) + "\n", encoding="utf-8")
    focused = repo / "src" / "z-sensitive.py"
    focused.write_text("browser_input = location.search\nrender(browser_input)\n", encoding="utf-8")
    findings = [
        {
            "file": "src/a-common.py",
            "line": index + 1,
            "category": 10,
            "subcategory": f"common-{index}",
            "severity": "High",
        }
        for index in range(bundles.MAX_SOURCE_SLICES + 5)
    ]
    findings.append(
        {
            "file": "src/z-sensitive.py",
            "line": 1,
            "category": 20,
            "subcategory": "distinct-source-sink",
            "severity": "High",
            "sink_line": 2,
        }
    )
    (output / ".recon-patterns.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")

    manifest = bundles.build_all(
        output,
        repo,
        _manifest(_component(focus_paths=["src/z-sensitive.py"])),
    )
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())

    assert len(bundle["source_slices"]) == bundles.MAX_SOURCE_SLICES
    assert {row["start_line"] for row in bundle["source_slices"] if row["path"] == "src/z-sensitive.py"} == {1, 2}
    assert bundle["path_routing"]["focus_admission"] == [
        {
            "path": "src/z-sensitive.py",
            "status": "admitted",
            "reason": "projected",
            "candidate_files": 1,
            "projected_files": ["src/z-sensitive.py"],
            "omitted_files": 0,
            "unowned_files": 0,
            "enumeration_truncated": False,
        }
    ]
    assert bundle["limits"]["referenced_source_lines"] <= bundles.MAX_SOURCE_LINES
    assert bundle["limits"]["serialized_bytes"] <= bundles.MAX_BUNDLE_BYTES
    assert bundle["limits"]["estimated_tokens"] <= bundles.MAX_ESTIMATED_TOKENS


def test_exclude_path_is_receipted_without_removing_bundle_evidence(tmp_path):
    repo, output = _repo(tmp_path)
    optional = repo / "src" / "optional"
    optional.mkdir()
    (optional / "helper.py").write_text("value = 1\n", encoding="utf-8")
    _write_signal(output)

    manifest = bundles.build_all(output, repo, _manifest(_component(exclude_paths="src/optional")))
    component = manifest["components"][0]
    bundle = json.loads((output / component["evidence_bundle_path"]).read_text())

    assert component["exclude_paths"] == ["src/optional"]
    assert bundle["source_slices"][0]["path"] == "src/app.py"
    assert bundle["path_routing"]["exclude_application"] == [
        {
            "path": "src/optional",
            "status": "applied",
            "scope": "optional-discovery-only",
            "superseded_by": [],
        }
    ]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("focus_paths", "", "empty or oversized"),
        ("focus_paths", "/etc", "unsafe repository-relative"),
        ("focus_paths", "https://example.invalid/source.py", "absolute path or URL"),
        ("focus_paths", "../outside.py", "unsafe repository-relative"),
        ("focus_paths", "src/*.py", "literal repository-relative"),
        ("exclude_paths", ["src/app.py"] * 17, "16-path cap"),
    ],
)
def test_routing_rejects_empty_unsafe_glob_and_oversized_inputs(tmp_path, field, value, message):
    repo, output = _repo(tmp_path)
    with pytest.raises(bundles.BundleError, match=message):
        bundles.build_all(output, repo, _manifest(_component(**{field: value})))


def test_routing_warns_and_skips_missing_focus_path(tmp_path, capsys):
    repo, output = _repo(tmp_path)
    # focus_paths names a file that does not exist in the repo — should warn, not abort
    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/nonexistent.py"])))
    captured = capsys.readouterr()
    assert "ROUTING_WARN" in captured.err
    assert "nonexistent.py" in captured.err
    # bundle still built; focus_paths is empty after the skip
    component = manifest["components"][0]
    assert component.get("focus_paths", []) == []


def test_producer_routing_gate_rejects_missing_focus_path(tmp_path):
    repo, _output = _repo(tmp_path)

    with pytest.raises(bundles.BundleError, match="does not exist"):
        bundles.validate_component_routing_values(
            "backend-api",
            ["src/**"],
            {"focus_paths": ["src/nonexistent.py"]},
            repo,
        )


def test_routing_rejects_path_outside_component_scope(tmp_path):
    repo, output = _repo(tmp_path)
    other = repo / "other.py"
    other.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(bundles.BundleError, match="outside the component paths"):
        bundles.build_all(output, repo, _manifest(_component(focus_paths=["other.py"])))


def test_producer_routing_gate_rejects_existing_path_outside_component_scope(tmp_path):
    repo, _output = _repo(tmp_path)
    (repo / "other.py").write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(bundles.BundleError, match="outside the component paths"):
        bundles.validate_component_routing_values(
            "backend-api",
            ["src/**"],
            {"focus_paths": ["other.py"]},
            repo,
        )


def test_focus_receipt_discloses_enumeration_limit(tmp_path, monkeypatch):
    repo, output = _repo(tmp_path)
    monkeypatch.setattr(bundles, "MAX_FOCUS_ENUM_ENTRIES", 0)

    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src"])))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    receipt = bundle["path_routing"]["focus_admission"][0]

    assert receipt["status"] == "omitted"
    assert receipt["reason"] == "enumeration-budget"
    assert receipt["enumeration_truncated"] is True


def test_routing_rejects_symlink_escape(tmp_path):
    repo, output = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("secret\n", encoding="utf-8")
    (repo / "src" / "linked.py").symlink_to(outside)
    with pytest.raises(bundles.BundleError, match="escapes registered repository root"):
        bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/linked.py"])))


def test_routing_rejects_focus_exclude_overlap(tmp_path):
    repo, output = _repo(tmp_path)
    with pytest.raises(bundles.BundleError, match="focus_paths and exclude_paths overlap"):
        bundles.build_all(
            output,
            repo,
            _manifest(_component(focus_paths=["src/app.py"], exclude_paths=["src"])),
        )


def test_exclude_cannot_hide_mandatory_deterministic_signal(tmp_path):
    """The exclude yields to the signal; the signal stays in the bundle.

    The guarded property is unchanged — an exclude may never hide mandatory or
    cited evidence — but it is now enforced by superseding the hint rather than
    aborting the run, so this asserts the evidence directly instead of settling
    for the fact that something was raised. The producer never sees the scanner
    artifacts that make a path protected and so cannot avoid the collision.
    """
    repo, output = _repo(tmp_path)
    _write_signal(output)

    manifest = bundles.build_all(output, repo, _manifest(_component(exclude_paths=["src/app.py"])))
    entry = manifest["components"][0]
    bundle = json.loads((output / entry["evidence_bundle_path"]).read_text())

    assert "src/app.py" in {row["path"] for row in bundle["source_slices"]}
    assert bundle["path_routing"]["exclude_paths"] == []
    assert bundle["path_routing"]["exclude_application"] == [
        {
            "path": "src/app.py",
            "status": "superseded",
            "scope": "optional-discovery-only",
            "superseded_by": ["src/app.py"],
        }
    ]
    # the manifest keeps the request; the receipt accounts for its supersession
    assert entry["exclude_paths"] == ["src/app.py"]
    bundles.validate_bundle(
        output / entry["evidence_bundle_path"],
        {"primary": repo},
        expected_component_id="backend-api",
        expected_sha256=entry["evidence_bundle_sha256"],
        output_dir=output,
        expected_focus_paths=entry["focus_paths"],
        expected_exclude_paths=entry["exclude_paths"],
    )


def test_exclude_cannot_hide_already_cited_index_evidence(tmp_path):
    """Same property for evidence cited by an index rather than by a scanner."""
    repo, output = _repo(tmp_path)
    context = output / ".dispatch-context" / "backend-api"
    context.mkdir(parents=True)
    prior = context / "prior-findings.json"
    prior.write_text(json.dumps([{"id": "F-001", "evidence": {"file": "src/app.py", "line": 1}}]))
    component = _component(exclude_paths=["src/app.py"])
    component["index_paths"]["prior_findings"] = ".dispatch-context/backend-api/prior-findings.json"

    manifest = bundles.build_all(output, repo, _manifest(component))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    receipt = bundle["path_routing"]["exclude_application"][0]

    assert receipt["status"] == "superseded"
    assert receipt["superseded_by"] == ["src/app.py"]
    assert bundle["path_routing"]["exclude_paths"] == []


def test_bundle_rejects_manifest_routing_drift(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    component = manifest["components"][0]
    bundle_path = output / component["evidence_bundle_path"]

    with pytest.raises(bundles.BundleError, match="focus paths do not match"):
        bundles.validate_bundle(
            bundle_path,
            {"primary": repo},
            expected_sha256=component["evidence_bundle_sha256"],
            expected_focus_paths=[],
            expected_exclude_paths=[],
            output_dir=output,
        )


def test_focus_projection_becomes_stale_when_source_changes(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    component = manifest["components"][0]
    bundle_path = output / component["evidence_bundle_path"]
    (repo / "src" / "app.py").write_text("def login(user):\n    return None\n", encoding="utf-8")

    with pytest.raises(bundles.BundleError, match="stale for repository|source slice changed"):
        bundles.validate_bundle(
            bundle_path,
            {"primary": repo},
            expected_sha256=component["evidence_bundle_sha256"],
            expected_focus_paths=["src/app.py"],
            expected_exclude_paths=[],
            output_dir=output,
        )


def test_bundle_rejects_inconsistent_focus_receipt(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest(_component(focus_paths=["src/app.py"])))
    bundle_path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["path_routing"]["focus_admission"][0]["omitted_files"] = 1
    payload = bundles._render_bundle(bundle)

    with pytest.raises(bundles.BundleError, match="focus admission counts are inconsistent"):
        bundles.validate_bundle_bytes(payload, {"primary": repo}, excluded_root=output)


def test_unrouted_v1_bundle_remains_resume_compatible(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest())
    bundle_path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle.pop("path_routing")
    payload = bundles._render_bundle(bundle)

    parsed = bundles.validate_bundle_bytes(
        payload,
        {"primary": repo},
        expected_focus_paths=[],
        expected_exclude_paths=[],
        excluded_root=output,
    )

    assert "path_routing" not in parsed


def test_routed_dispatch_rejects_legacy_bundle_without_routing_receipt(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest())
    bundle_path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle.pop("path_routing")
    payload = bundles._render_bundle(bundle)

    with pytest.raises(bundles.BundleError, match="path routing is missing"):
        bundles.validate_bundle_bytes(
            payload,
            {"primary": repo},
            expected_focus_paths=["src/app.py"],
            expected_exclude_paths=[],
            excluded_root=output,
        )


def test_bundle_discloses_per_class_and_value_truncation(tmp_path):
    repo, output = _repo(tmp_path)
    values = [f"route-{index}" for index in range(40)] + ["x" * 5000]
    manifest = bundles.build_all(output, repo, _manifest(_component(interfaces=values)))
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())
    rows = {row["signal_class"]: row for row in bundle["truncation"]}
    assert rows["interfaces"]["original_count"] == 41
    assert rows["interfaces"]["retained_count"] == 32
    assert rows["interfaces"]["omitted_count"] == 9
    assert any(record["truncated"] for record in bundle["evidence"]["interfaces"])
    assert "interfaces.value_chars" in rows


def test_bundle_global_size_cap_drops_records_deterministically(tmp_path):
    repo, output = _repo(tmp_path)
    large = [f"{index:02d}-" + "x" * 4090 for index in range(32)]
    component = _component(interfaces=large, controls=large)
    manifest = bundles.build_all(output, repo, _manifest(component))
    payload = (output / manifest["components"][0]["evidence_bundle_path"]).read_bytes()
    bundle = json.loads(payload)
    assert len(payload) <= bundles.MAX_BUNDLE_BYTES
    assert any(row["omitted_count"] for row in bundle["truncation"])


def test_bundle_rejects_source_escape(tmp_path):
    repo, output = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("secret\n", encoding="utf-8")
    _write_signal(output, file="../outside.py")
    with pytest.raises(bundles.BundleError, match="unsafe repository-relative path"):
        bundles.build_all(output, repo, _manifest(_component(component_paths=["**"])))


def test_bundle_rejects_source_symlink_escape(tmp_path):
    repo, output = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("secret\n", encoding="utf-8")
    (repo / "src" / "linked.py").symlink_to(outside)
    _write_signal(output, file="src/linked.py")
    with pytest.raises(bundles.BundleError, match="escapes registered repository root"):
        bundles.build_all(output, repo, _manifest())


def test_bundle_rejects_unknown_source_repository(tmp_path):
    repo, output = _repo(tmp_path)
    _write_signal(output, repository_id="repo-from-untrusted-data")
    with pytest.raises(bundles.BundleError, match="unknown repository id"):
        bundles.build_all(output, repo, _manifest())


def test_bundle_fingerprints_only_related_roots_used_by_component_slices(tmp_path):
    repo, output = _repo(tmp_path)
    related_a = tmp_path / "related-a"
    related_b = tmp_path / "related-b"
    for related in (related_a, related_b):
        related.mkdir()
        _git(related, "init", "-b", "main")
        _git(related, "config", "user.email", "test@example.invalid")
        _git(related, "config", "user.name", "Test")
        source = related / "src" / "service.py"
        source.parent.mkdir()
        source.write_text("value = True\n", encoding="utf-8")
        _git(related, "add", "src/service.py")
        _git(related, "commit", "-m", "fixture")
    _write_signal(output, repository_id="related-a", file="src/service.py")
    registry = {"primary": repo, "related-a": related_a, "related-b": related_b}

    bundle, payload = bundles.build_bundle(output, _component(), registry)

    assert {row["repository_id"] for row in bundle["repository_state"]} == {"primary", "related-a"}
    assert {row["repository_id"] for row in bundle["source_slices"]} == {"related-a"}
    bundles.validate_bundle_bytes(payload, registry, expected_component_id="backend-api", excluded_root=output)

    (related_b / "src" / "service.py").write_text("unrelated = True\n", encoding="utf-8")
    bundles.validate_bundle_bytes(payload, registry, expected_component_id="backend-api", excluded_root=output)


def test_bundle_rejects_repository_state_for_unreferenced_related_root(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest())
    bundle_path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["repository_state"].append(
        {
            "repository_id": "unrelated",
            "kind": "related",
            "commit_sha": "0" * 40,
            "dirty_worktree_sha256": "0" * 64,
        }
    )
    payload = bundles._render_bundle(bundle)

    with pytest.raises(bundles.BundleError, match="does not match its admitted source slices"):
        bundles.validate_bundle_bytes(payload, {"primary": repo}, excluded_root=output)


def test_bundle_accepts_safe_source_paths_with_spaces_and_unicode(tmp_path):
    repo, output = _repo(tmp_path)
    source = repo / "src" / "über uns.py"
    source.write_text("safe = True\n", encoding="utf-8")
    _write_signal(output, file="src/über uns.py")

    manifest = bundles.build_all(output, repo, _manifest())
    bundle = json.loads((output / manifest["components"][0]["evidence_bundle_path"]).read_text())

    assert bundle["source_slices"][0]["path"] == "src/über uns.py"


def test_bundle_becomes_stale_when_source_bytes_change(tmp_path):
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = bundles.build_all(output, repo, _manifest())
    component = manifest["components"][0]
    bundle_path = output / component["evidence_bundle_path"]
    (repo / "src" / "app.py").write_text("def login(user):\n    return None\n", encoding="utf-8")

    with pytest.raises(bundles.BundleError, match="stale for repository|source slice changed"):
        bundles.validate_bundle(
            bundle_path,
            {"primary": repo},
            expected_sha256=component["evidence_bundle_sha256"],
            output_dir=output,
        )


def test_bundle_becomes_stale_when_source_change_is_staged(tmp_path):
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = bundles.build_all(output, repo, _manifest())
    component = manifest["components"][0]
    bundle_path = output / component["evidence_bundle_path"]
    (repo / "src" / "app.py").write_text("def login(user):\n    return None\n", encoding="utf-8")
    _git(repo, "add", "src/app.py")

    with pytest.raises(bundles.BundleError, match="stale for repository"):
        bundles.validate_bundle(
            bundle_path,
            {"primary": repo},
            expected_sha256=component["evidence_bundle_sha256"],
            output_dir=output,
        )


def test_unrelated_repository_churn_does_not_invalidate_a_bundle(tmp_path):
    """Files the bundle never cites must not abort a run when they change.

    A long STRIDE phase runs against a live checkout: editors save, watchers
    write, builds emit. None of that touches what the bundle asserts.
    """
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = bundles.build_all(output, repo, _manifest())
    component = manifest["components"][0]
    bundle_path = output / component["evidence_bundle_path"]

    (repo / "UNRELATED.md").write_text("noise\n", encoding="utf-8")
    (repo / "src" / "other.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "src/other.py")
    (repo / ".appsec-progress.json").write_text('{"event": "STEP_END"}\n', encoding="utf-8")

    bundle = bundles.validate_bundle(
        bundle_path,
        {"primary": repo},
        expected_sha256=component["evidence_bundle_sha256"],
        output_dir=output,
    )
    assert bundle["component"]["id"] == component["component_id"]


def test_a_commit_that_leaves_cited_bytes_alone_does_not_invalidate(tmp_path):
    """An actively developed repository must not lose a run to its own history."""
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = bundles.build_all(output, repo, _manifest())
    component = manifest["components"][0]

    (repo / "CHANGELOG.md").write_text("unrelated\n", encoding="utf-8")
    _git(repo, "add", "CHANGELOG.md")
    _git(repo, "commit", "-m", "unrelated work during the scan")

    bundles.validate_bundle(
        output / component["evidence_bundle_path"],
        {"primary": repo},
        expected_sha256=component["evidence_bundle_sha256"],
        output_dir=output,
    )


def test_a_commit_that_rewrites_a_cited_file_still_invalidates(tmp_path):
    repo, output = _repo(tmp_path)
    _write_signal(output)
    manifest = bundles.build_all(output, repo, _manifest())
    component = manifest["components"][0]

    (repo / "src" / "app.py").write_text("def login(user):\n    return None\n", encoding="utf-8")
    _git(repo, "add", "src/app.py")
    _git(repo, "commit", "-m", "touch the cited file")

    with pytest.raises(bundles.BundleError, match="stale for repository"):
        bundles.validate_bundle(
            output / component["evidence_bundle_path"],
            {"primary": repo},
            expected_sha256=component["evidence_bundle_sha256"],
            output_dir=output,
        )


def test_fingerprint_covers_only_the_cited_files(tmp_path):
    repo, output = _repo(tmp_path)
    cited = ["src/app.py"]
    _, before = bundles.repository_fingerprint(repo, cited_paths=cited, excluded_root=output)

    (repo / "src" / "other.py").write_text("x = 1\n", encoding="utf-8")
    _, unrelated = bundles.repository_fingerprint(repo, cited_paths=cited, excluded_root=output)
    assert unrelated == before

    (repo / "src" / "app.py").write_text("def login(user):\n    return None\n", encoding="utf-8")
    _, changed = bundles.repository_fingerprint(repo, cited_paths=cited, excluded_root=output)
    assert changed != before


def test_fingerprint_ignores_citations_inside_the_output_directory(tmp_path):
    """Run-owned output must never bind a bundle, whatever cites it."""
    repo, output = _repo(tmp_path)
    summary = output / ".recon-summary.md"
    summary.write_text("first\n", encoding="utf-8")
    cited = ["docs/security/.recon-summary.md"]

    _, before = bundles.repository_fingerprint(repo, cited_paths=cited, excluded_root=output)
    summary.write_text("rewritten mid-run\n", encoding="utf-8")
    _, after = bundles.repository_fingerprint(repo, cited_paths=cited, excluded_root=output)
    assert after == before


def test_bundle_rejects_changed_bundle_bytes(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest())
    component = manifest["components"][0]
    path = output / component["evidence_bundle_path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(bundles.BundleError, match="fingerprint"):
        bundles.validate_bundle(
            path,
            {"primary": repo},
            expected_sha256=component["evidence_bundle_sha256"],
            output_dir=output,
        )


def test_bundle_rejects_malformed_component_index(tmp_path):
    repo, output = _repo(tmp_path)
    context = output / ".dispatch-context" / "backend-api"
    context.mkdir(parents=True)
    (context / "known-threats.json").write_text("{broken", encoding="utf-8")
    component = _component()
    component["index_paths"]["known_threats"] = ".dispatch-context/backend-api/known-threats.json"
    with pytest.raises(bundles.BundleError, match="component index is unreadable"):
        bundles.build_all(output, repo, _manifest(component))


def test_bundle_rejects_duplicate_component_ids(tmp_path):
    repo, output = _repo(tmp_path)
    with pytest.raises(bundles.BundleError, match="duplicate component id"):
        bundles.build_all(output, repo, _manifest(_component(), _component()))


def test_related_repository_registry_requires_related_repos_declaration(tmp_path):
    repo, _ = _repo(tmp_path)
    related = tmp_path / "related"
    related.mkdir()
    threat_model = related / "threat-model.yaml"
    threat_model.write_text("meta: {}\n", encoding="utf-8")
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repositories": [
                    {
                        "repository_id": "related",
                        "kind": "related",
                        "root": str(related),
                        "declared_name": "related-service",
                        "declared_threat_model": str(threat_model),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(bundles.BundleError, match="does not match"):
        bundles.load_repository_registry(repo, registry_path)


def test_related_repository_registry_accepts_exact_local_declaration(tmp_path):
    repo, _ = _repo(tmp_path)
    related = tmp_path / "related"
    related.mkdir()
    _git(related, "init", "-b", "main")
    threat_model = related / "docs" / "security" / "threat-model.yaml"
    threat_model.parent.mkdir(parents=True)
    threat_model.write_text("meta: {}\n", encoding="utf-8")
    docs = repo / "docs"
    docs.mkdir(exist_ok=True)
    (docs / "related-repos.yaml").write_text(
        f"related:\n  - name: related-service\n    threat_model: {threat_model}\n",
        encoding="utf-8",
    )
    registry_path = tmp_path / "registry.json"
    bundles.write_repository_registry(repo, registry_path)
    assert bundles.load_repository_registry(repo, registry_path) == {
        "primary": repo.resolve(),
        "related-service": related.resolve(),
    }


def test_repository_registry_omits_remote_and_non_git_declarations(tmp_path):
    repo, _ = _repo(tmp_path)
    non_git = tmp_path / "non-git" / "threat-model.yaml"
    non_git.parent.mkdir()
    non_git.write_text("meta: {}\n", encoding="utf-8")
    (repo / "docs" / "related-repos.yaml").write_text(
        "related:\n"
        "  - name: remote\n"
        "    threat_model: https://example.invalid/threat-model.yaml\n"
        "  - name: local-non-git\n"
        f"    threat_model: {non_git}\n",
        encoding="utf-8",
    )

    assert bundles.repository_registry_document(repo) == {"schema_version": 1, "repositories": []}


def test_repository_registry_rejects_duplicate_declared_names(tmp_path):
    repo, _ = _repo(tmp_path)
    (repo / "docs" / "related-repos.yaml").write_text(
        "related:\n"
        "  - name: repeated\n"
        "    threat_model: ../one/threat-model.yaml\n"
        "  - name: repeated\n"
        "    threat_model: ../two/threat-model.yaml\n",
        encoding="utf-8",
    )

    with pytest.raises(bundles.BundleError, match="duplicate name"):
        bundles.repository_registry_document(repo)


def test_repository_registry_rejects_primary_repo_registered_as_related(tmp_path):
    repo, output = _repo(tmp_path)
    threat_model = output / "threat-model.yaml"
    threat_model.write_text("meta: {}\n", encoding="utf-8")
    (repo / "docs" / "related-repos.yaml").write_text(
        f"related:\n  - name: self\n    threat_model: {threat_model}\n",
        encoding="utf-8",
    )

    with pytest.raises(bundles.BundleError, match="reuses a registered git root"):
        bundles.repository_registry_document(repo)


def test_repository_registry_rejects_malformed_declaration_yaml(tmp_path):
    repo, _ = _repo(tmp_path)
    (repo / "docs" / "related-repos.yaml").write_text("related: [\n", encoding="utf-8")

    with pytest.raises(bundles.BundleError, match="declaration is unreadable"):
        bundles.repository_registry_document(repo)


def test_bundle_rejects_duplicate_repository_state_ids(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest())
    path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(path.read_text(encoding="utf-8"))
    bundle["repository_state"].append(dict(bundle["repository_state"][0]))
    payload = bundles._render_bundle(bundle)

    with pytest.raises(bundles.BundleError, match="duplicate repository ids"):
        bundles.validate_bundle_bytes(payload, {"primary": repo}, excluded_root=output)


def test_bundle_schema_rejects_primary_repository_with_related_kind(tmp_path):
    repo, output = _repo(tmp_path)
    manifest = bundles.build_all(output, repo, _manifest())
    path = output / manifest["components"][0]["evidence_bundle_path"]
    bundle = json.loads(path.read_text(encoding="utf-8"))
    bundle["repository_state"][0]["kind"] = "related"
    payload = bundles._render_bundle(bundle)

    with pytest.raises(bundles.BundleError, match="schema validation failed"):
        bundles.validate_bundle_bytes(payload, {"primary": repo}, excluded_root=output)


def test_cli_writes_manifest_and_bundle(tmp_path):
    repo, output = _repo(tmp_path)
    manifest_path = output / ".stride-dispatch-manifest.json"
    manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
    assert (
        bundles.main(
            [
                "--output-dir",
                str(output),
                "--repo-root",
                str(repo),
                "--manifest",
                str(manifest_path),
            ]
        )
        == 0
    )
    manifest = json.loads(manifest_path.read_text())
    assert manifest["context_version"] == 2
    assert (output / manifest["components"][0]["evidence_bundle_path"]).is_file()
