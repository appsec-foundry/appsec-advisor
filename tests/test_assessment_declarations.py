"""Repository-owned declarations stay qualified in a combined assessment."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts.build_trust_boundary_assessment_input import assessment_source_context
from contexts.prepare_trust_boundary_context import normalize_assessment_boundaries
from model import resolve_actors
from orchestrator import assessment_declarations as declarations
from orchestrator.assessment_workspace import Namespaces
from runtime.multi_repo_scope import admit
from shared import _url_guard

NAMES = [("edge", "service"), ("gateway", "billing")]


def checkouts(tmp_path, names, files, remotes=None):
    roots = []
    for name in names:
        root = tmp_path / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        identity = ["-c", "user.name=Test", "-c", "user.email=test@example.invalid"]
        subprocess.run(["git", "-C", str(root), *identity, "commit", "-q", "--allow-empty", "-m", "init"], check=True)
        if remotes and name in remotes:
            subprocess.run(["git", "-C", str(root), "remote", "add", "origin", remotes[name]], check=True)
        (root / "app.py").write_text("handler = route(payload)\n")
        for relative, value in files.get(name, {}).items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(value if isinstance(value, str) else yaml.safe_dump(value))
        roots.append(root)
    return admit([str(root) for root in roots], str(tmp_path / "out"), minimum=1)


def qualified_components(scope):
    cards = []
    for index, repo in enumerate(sorted(scope.repositories, key=lambda r: r.root.name), 1):
        sha = hashlib.sha256(repo.files["app.py"]).hexdigest()
        cards.append(
            dict(
                id=f"component-{index}",
                local_id="api",
                name=f"{repo.root.name.title()} API",
                description="Application service.",
                tier="application",
                repository_ids=[repo.repository_id],
                paths=[dict(repository_id=repo.repository_id, path="app.py", sha256=sha)],
            )
        )
    return dict(schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], components=cards)


def boundaries(*rows):
    return {"api_version": "appsec-advisor/trust-boundaries/v1", "boundaries": list(rows)}


def boundary(target, **extra):
    return dict(
        key="public-ingress",
        name="Public ingress",
        kind="network",
        assumption="Every request must carry a session the receiver validates.",
        **{"from": "external", "to": target},
        **extra,
    )


@pytest.mark.parametrize("names", NAMES)
def test_boundary_declaration_applies_only_to_its_own_repository(tmp_path, names):
    first, second = names
    declared = boundaries(boundary("api", evidence=[{"file": "app.py", "line": 1}]))
    scope = checkouts(tmp_path, names, {second: {".appsec/trust-boundaries.yaml": declared}})
    components = qualified_components(scope)
    owner = next(r for r in scope.repositories if r.root.name == second).repository_id
    own = next(c["id"] for c in components["components"] if c["repository_ids"] == [owner])

    rows = declarations.boundary_declarations(scope, components)
    assert [(row["from"], row["to"], row["key"]) for row in rows] == [("external", own, f"{second}-public-ingress")]
    assert rows[0]["evidence"][0]["repository_id"] == owner
    assert assessment_source_context(scope)["boundary_declarations"]["keys"] == [f"{second}-public-ingress"]

    scope.output.mkdir()
    document, _ = normalize_assessment_boundaries(scope, components, [], output_dir=scope.output, declarations=rows)
    (row,) = document["trust_boundaries"]
    assert row["to"] == own and row["sources"] == ["repo-declared"]
    # A declaration adds a crossing; it never confirms the control.
    assert row["confidence"] == "inferred"


@pytest.mark.parametrize(
    ("target", "evidence", "message"),
    [
        ("{first} api", None, "another repository"),
        ("nowhere", None, "names no component"),
        ("api", [{"file": "missing.py", "line": 1}], "not a captured line"),
        ("api", [{"file": "app.py", "line": 40}], "not a captured line"),
    ],
)
def test_declaration_reaching_beyond_its_repository_stops_the_run(tmp_path, target, evidence, message):
    first, second = NAMES[0]
    row = boundary(target.format(first=first.title()), **({"evidence": evidence} if evidence else {}))
    scope = checkouts(tmp_path, NAMES[0], {second: {".appsec/trust-boundaries.yaml": boundaries(row)}})
    with pytest.raises(declarations.DeclarationError, match=message):
        declarations.boundary_declarations(scope, qualified_components(scope))


def test_invalid_boundary_declaration_stops_before_analysis(tmp_path):
    scope = checkouts(tmp_path, NAMES[0], {"service": {".appsec/trust-boundaries.yaml": "boundaries: []\n"}})
    with pytest.raises(declarations.DeclarationError, match="service/.appsec/trust-boundaries.yaml"):
        assessment_source_context(scope)


@pytest.mark.parametrize("name", ["service", "order-portal"])
def test_sole_repository_declaration_keeps_its_own_keys_and_paths(tmp_path, name):
    """One repository names nothing to tell apart: keys and paths stay as declared (MR-3)."""
    declared = boundaries(boundary("api", evidence=[{"file": "app.py", "line": 1}]))
    scope = checkouts(tmp_path, [name], {name: {".appsec/trust-boundaries.yaml": declared}})
    rows = declarations.boundary_declarations(scope, qualified_components(scope))
    assert [row["key"] for row in rows] == ["public-ingress"]
    assert assessment_source_context(scope)["boundary_declarations"]["keys"] == ["public-ingress"]
    names = Namespaces(scope)
    rid = scope.repositories[0].repository_id
    assert declarations._actor_evidence(name, {"files": ["app.py"]}, names, rid) == {"files": ["app.py"]}


def test_two_repositories_keep_namespaced_declaration_paths(tmp_path):
    scope = checkouts(tmp_path, NAMES[0], {})
    names = Namespaces(scope)
    edge = next(r for r in scope.repositories if r.root.name == "edge")
    evidence = declarations._actor_evidence("edge", {"files": ["app.py"]}, names, edge.repository_id)
    assert evidence == {"files": ["edge/app.py"]}


def test_sole_repository_actor_file_is_named_by_its_plain_path(tmp_path):
    files = {"api": {".appsec/actors.yaml": {"actors": [repo_actor("ACT-R-001", "partner-operator")]}}}
    scope = checkouts(tmp_path, ["api"], files)
    root, workspace = tmp_path / "combined", tmp_path / "workspace"
    root.mkdir()
    workspace.mkdir()
    installed = declarations.install_actor_config(scope, Namespaces(scope), root)
    resolve_actors.resolve(
        plugin_root=str(declarations.PLUGIN_ROOT), repo_root=str(root), output_dir=str(workspace), quick_mode=True
    )
    declarations.attribute_actor_owners(workspace, installed["owners"], single=True)
    resolved = json.loads((workspace / ".actors-resolved.json").read_text())["resolved_actors"]
    (custom,) = [a for a in resolved if a["id"].startswith("ACT-R-")]
    assert custom["_provenance"]["source_file"] == ".appsec/actors.yaml"


def repo_actor(actor_id, label):
    return {
        "id": actor_id,
        "label": label,
        "access": ["internal-network"],
        "capabilities": {"sophistication": "medium", "dwell_time": "weeks", "surface_reach": ["lateral"]},
        "motivation": "financial",
        "heatmap_slug": "repo-read",
    }


@pytest.mark.parametrize("names", NAMES)
def test_same_actor_id_in_two_repositories_stays_distinct_with_owners(tmp_path, names):
    files = {name: {".appsec/actors.yaml": {"actors": [repo_actor("ACT-R-001", "partner-operator")]}} for name in names}
    scope = checkouts(tmp_path, names, files)
    root, workspace = tmp_path / "combined", tmp_path / "workspace"
    root.mkdir()
    workspace.mkdir()
    installed = declarations.install_actor_config(scope, Namespaces(scope), root)
    resolve_actors.resolve(
        plugin_root=str(declarations.PLUGIN_ROOT), repo_root=str(root), output_dir=str(workspace), quick_mode=True
    )
    declarations.attribute_actor_owners(workspace, installed["owners"])

    resolved = json.loads((workspace / ".actors-resolved.json").read_text())["resolved_actors"]
    custom = {a["id"]: a for a in resolved if a["id"].startswith("ACT-R-")}
    assert len(custom) == 2
    assert sorted(a["_provenance"]["source_file"] for a in custom.values()) == sorted(
        f"{name}/.appsec/actors.yaml" for name in names
    )
    assert len({a["label"] for a in custom.values()}) == 2


def test_disable_applies_only_when_every_repository_declares_it(tmp_path):
    default = resolve_actors.load_plugin_defaults(str(declarations.PLUGIN_ROOT))[0]["id"]
    files = {"edge": {".appsec/actors.yaml": {"disable": [{"id": default, "reason": "no public surface"}]}}}
    scope = checkouts(tmp_path, NAMES[0], files)
    declared = declarations.actor_declarations(scope, Namespaces(scope))
    assert "disable" not in declared["config"]
    assert any(default in receipt for receipt in declared["receipts"])

    files["service"] = files["edge"]
    (tmp_path / "all").mkdir()
    scope = checkouts(tmp_path / "all", NAMES[0], files)
    declared = declarations.actor_declarations(scope, Namespaces(scope))
    assert [row["id"] for row in declared["config"]["disable"]] == [default]


def test_conflicting_default_actor_overrides_stop_the_run(tmp_path):
    default = resolve_actors.load_plugin_defaults(str(declarations.PLUGIN_ROOT))[0]["id"]
    files = {
        name: {".appsec/actors.yaml": {"actors": [{"id": default, "motivation": motivation}]}}
        for name, motivation in zip(NAMES[0], ("financial", "curiosity"), strict=True)
    }
    scope = checkouts(tmp_path, NAMES[0], files)
    with pytest.raises(declarations.DeclarationError, match="differently"):
        declarations.actor_declarations(scope, Namespaces(scope))


def related(*entries):
    return {"related": [dict(name=name, threat_model=ref) for name, ref in entries]}


@pytest.mark.parametrize("names", NAMES)
def test_import_of_a_selected_repository_yields_to_its_current_assessment(tmp_path, names, monkeypatch):
    first, second = names
    monkeypatch.setattr(_url_guard, "_active_allowlist", lambda: None)
    remote = f"https://git.example.invalid/team/{second}.git"
    imports = related(
        (f"{second}-by-path", f"../{second}/docs/security/threat-model.yaml"),
        (f"{second}-by-remote", f"https://git.example.invalid/team/{second}/-/raw/main/docs/threat-model.yaml"),
        ("ledger", "https://models.example.invalid/ledger/threat-model.yaml"),
        ("archive", "/srv/models/archive/threat-model.yaml"),
    )
    scope = checkouts(tmp_path, names, {first: {"docs/related-repos.yaml": imports}}, remotes={second: remote})
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    receipts = declarations.related_register(scope, Namespaces(scope), workspace, {})

    register = json.loads((workspace / ".cross-repo-register.json").read_text())
    assert [row["selected_repository"] for row in register["meta"]["authoritative_current"]] == [second, second]
    kept = {row["name"]: row for row in register["entries"]}
    assert set(kept) == {"ledger", "archive"}
    assert {row["discovery_hint"] for row in kept.values()} == {f"{first}/docs/related-repos.yaml"}
    # The strict URL rule still applies: without an allow-list nothing is fetched.
    assert "APPSEC_URL_ALLOWLIST" in kept["ledger"]["threat_model"]["fetch_detail"]
    # A local path outside the selected roots is named, never read.
    assert kept["archive"]["threat_model"]["status"] == "unavailable"
    assert any("authoritative" in receipt for receipt in receipts)


def test_allow_list_still_rejects_an_unlisted_host(tmp_path, monkeypatch):
    monkeypatch.setattr(_url_guard, "_active_allowlist", lambda: ["models.example.invalid"])
    imports = related(("ledger", "https://elsewhere.example.invalid/threat-model.yaml"))
    scope = checkouts(tmp_path, NAMES[0], {"edge": {"docs/related-repos.yaml": imports}})
    (tmp_path / "workspace").mkdir()
    declarations.related_register(scope, Namespaces(scope), tmp_path / "workspace", {"trust_mode": "trusted"})
    register = json.loads((tmp_path / "workspace" / ".cross-repo-register.json").read_text())
    assert "not in APPSEC_URL_ALLOWLIST" in register["entries"][0]["threat_model"]["fetch_detail"]


def test_invalid_related_declaration_stops_the_run(tmp_path):
    scope = checkouts(tmp_path, NAMES[0], {"edge": {"docs/related-repos.yaml": {"related": [{"name": "x"}]}}})
    with pytest.raises(declarations.DeclarationError, match="edge/docs/related-repos.yaml"):
        declarations.related_register(scope, Namespaces(scope), tmp_path, {})


def test_no_declarations_write_nothing(tmp_path):
    scope = checkouts(tmp_path, NAMES[0], {})
    names = Namespaces(scope)
    assert declarations.related_register(scope, names, tmp_path, {}) == []
    assert not (tmp_path / ".cross-repo-register.json").exists()
    assert declarations.actor_declarations(scope, names) is None
    assert declarations.boundary_declarations(scope, qualified_components(scope)) == []
