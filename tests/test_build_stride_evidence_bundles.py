from __future__ import annotations

import hashlib
import json
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
            "enumeration_truncated": False,
        }
    ]


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
        {"path": "src/optional", "status": "applied", "scope": "optional-discovery-only"}
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


def test_routing_rejects_path_outside_component_scope(tmp_path):
    repo, output = _repo(tmp_path)
    other = repo / "other.py"
    other.write_text("value = 1\n", encoding="utf-8")
    with pytest.raises(bundles.BundleError, match="outside the component paths"):
        bundles.build_all(output, repo, _manifest(_component(focus_paths=["other.py"])))


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


def test_exclude_rejects_mandatory_deterministic_signal(tmp_path):
    repo, output = _repo(tmp_path)
    _write_signal(output)
    with pytest.raises(bundles.BundleError, match="hide mandatory or cited evidence"):
        bundles.build_all(output, repo, _manifest(_component(exclude_paths=["src/app.py"])))


def test_exclude_rejects_already_cited_index_evidence(tmp_path):
    repo, output = _repo(tmp_path)
    context = output / ".dispatch-context" / "backend-api"
    context.mkdir(parents=True)
    prior = context / "prior-findings.json"
    prior.write_text(json.dumps([{"id": "F-001", "evidence": {"file": "src/app.py", "line": 1}}]))
    component = _component(exclude_paths=["src/app.py"])
    component["index_paths"]["prior_findings"] = ".dispatch-context/backend-api/prior-findings.json"

    with pytest.raises(bundles.BundleError, match="hide mandatory or cited evidence"):
        bundles.build_all(output, repo, _manifest(component))


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
