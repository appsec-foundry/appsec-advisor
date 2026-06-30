"""Unit tests for scripts/resolve_actors.py — 4-layer actor resolver."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import resolve_actors
import yaml


# ---------------------------------------------------------------------------
# Fixtures: a self-contained plugin-root with a controlled default-library.yaml
# ---------------------------------------------------------------------------
def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))


@pytest.fixture
def plugin_lib(tmp_path: Path) -> Path:
    """Create a plugin-root dir with data/actors/default-library.yaml."""
    proot = tmp_path / "plugin"
    lib = {
        "schema_version": 1,
        "actors": [
            {
                "id": "ACT-D-01",
                "label": "anon-attacker",
                "access": ["internet"],
                "trust_positions": ["public-endpoint-reach"],
                "activation_conditions": {"required_signals": ["has_public_routes"]},
            },
            {
                "id": "ACT-D-02",
                "label": "auth-user",
                "access": ["authenticated-user-session"],
                "trust_positions": ["authenticated-user-authority"],
                "activation_conditions": {
                    "required_signals": ["has_auth_surface", "has_role_concept"],
                    "signal_logic": "any",
                },
            },
            {
                "id": "ACT-D-03",
                "label": "always-on",
                "access": ["internal"],
                "trust_positions": ["internal-system-authority"],
            },
        ],
        "reach_equivalence_rules": [
            {
                "condition_signal": "has_open_self_registration",
                "actor_ids": ["ACT-D-01", "ACT-D-02"],
                "collapse_reason": "self-reg-open",
                "primary_actor": "ACT-D-01",
                "note": "anon == low-priv when registration is open",
            }
        ],
    }
    _write_yaml(proot / "data" / "actors" / "default-library.yaml", lib)
    return proot


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def test_load_yaml_empty(tmp_path: Path):
    p = tmp_path / "empty.yaml"
    p.write_text("")
    assert resolve_actors._load_yaml(str(p)) == {}


def test_load_json(tmp_path: Path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"a": 1}))
    assert resolve_actors._load_json(str(p)) == {"a": 1}


def test_deep_merge_scalar_override_and_list_union():
    base = {"id": "A", "access": ["x", "y"], "label": "old", "_provenance": {"layer": "p"}}
    override = {"access": ["y", "z"], "label": "new", "_skip": "ignored"}
    out = resolve_actors._deep_merge_actor(base, override)
    assert out["label"] == "new"
    assert out["access"] == ["x", "y", "z"]  # union, order preserved
    # underscore keys skipped
    assert "_skip" not in out
    # base untouched
    assert base["label"] == "old"


def test_activation_no_conditions():
    ok, reason = resolve_actors._activation_check({}, {"has_x": True})
    assert ok and "no conditions" in reason


def test_activation_no_signals_warning():
    actor = {"activation_conditions": {"required_signals": ["has_x"]}}
    ok, reason = resolve_actors._activation_check(actor, {})
    assert ok and "signals not available" in reason


def test_activation_any_logic_met_and_unmet():
    actor = {"activation_conditions": {"required_signals": ["a", "b"], "signal_logic": "any"}}
    ok, reason = resolve_actors._activation_check(actor, {"a": True})
    assert ok and "signal(s) met" in reason
    ok2, reason2 = resolve_actors._activation_check(actor, {"a": False, "b": False})
    assert not ok2 and "no signal" in reason2


def test_activation_all_logic_met_and_unmet():
    actor = {"activation_conditions": {"required_signals": ["a", "b"]}}
    ok, reason = resolve_actors._activation_check(actor, {"a": True, "b": True})
    assert ok and "all required signals" in reason
    ok2, reason2 = resolve_actors._activation_check(actor, {"a": True})
    assert not ok2 and "not set: b" in reason2


def test_check_stale_no_evidence():
    assert resolve_actors._check_stale({}, "/tmp") is False


def test_check_stale_empty_pattern_or_files(tmp_path: Path):
    assert resolve_actors._check_stale({"evidence": {"pattern": "", "files": ["a"]}}, str(tmp_path)) is False
    assert resolve_actors._check_stale({"evidence": {"pattern": "p", "files": []}}, str(tmp_path)) is False


def test_check_stale_no_matched_files(tmp_path: Path):
    # glob matches nothing -> loop continues -> returns True (pattern matched no file)
    actor = {"evidence": {"pattern": "needle", "files": ["does/not/exist/*.py"]}}
    assert resolve_actors._check_stale(actor, str(tmp_path)) is True


def test_check_stale_rg_missing_returns_false(tmp_path: Path, monkeypatch):
    # A file exists matching the glob; force rg lookup to raise FileNotFoundError.
    (tmp_path / "src.py").write_text("hello")

    def _boom(*a, **k):
        raise FileNotFoundError("rg")

    monkeypatch.setattr(resolve_actors.subprocess, "run", _boom)
    actor = {"evidence": {"pattern": "needle", "files": ["src.py"]}}
    assert resolve_actors._check_stale(actor, str(tmp_path)) is False


def test_check_stale_rg_match_returns_false(tmp_path: Path, monkeypatch):
    (tmp_path / "src.py").write_text("needle")

    class _R:
        returncode = 0
        stdout = "src.py\n"

    monkeypatch.setattr(resolve_actors.subprocess, "run", lambda *a, **k: _R())
    actor = {"evidence": {"pattern": "needle", "files": ["src.py"]}}
    assert resolve_actors._check_stale(actor, str(tmp_path)) is False


def test_check_stale_rg_no_match_returns_true(tmp_path: Path, monkeypatch):
    (tmp_path / "src.py").write_text("nomatch")

    class _R:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(resolve_actors.subprocess, "run", lambda *a, **k: _R())
    actor = {"evidence": {"pattern": "needle", "files": ["src.py"]}}
    assert resolve_actors._check_stale(actor, str(tmp_path)) is True


def test_sha256():
    assert resolve_actors._sha256("abc") == resolve_actors._sha256("abc")
    assert len(resolve_actors._sha256("abc")) == 64


def test_parse_disables_str_and_dict():
    out = resolve_actors._parse_disables(["ACT-1", {"id": "ACT-2", "reason": "r"}, {"noid": 1}, 5])
    assert out == [
        {"id": "ACT-1", "reason": None},
        {"id": "ACT-2", "reason": "r"},
    ]
    assert resolve_actors._parse_disables(None) == []


def test_compute_fingerprint_stable(plugin_lib: Path, tmp_path: Path):
    fp1 = resolve_actors._compute_actors_inputs_fingerprint(str(plugin_lib), "", "", str(tmp_path))
    fp2 = resolve_actors._compute_actors_inputs_fingerprint(str(plugin_lib), "", "", str(tmp_path))
    assert fp1 == fp2 and len(fp1) == 64


def test_compute_fingerprint_includes_repo_and_enterprise(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    _write_yaml(repo / ".appsec" / "actors.yaml", {"actors": []})
    profile = tmp_path / "profile"
    _write_yaml(profile / "actors" / "x.yaml", {"actors": []})
    fp = resolve_actors._compute_actors_inputs_fingerprint(str(plugin_lib), str(profile), "actors/*.yaml", str(repo))
    assert len(fp) == 64


# ---------------------------------------------------------------------------
# layer loaders
# ---------------------------------------------------------------------------
def test_load_plugin_defaults_missing(tmp_path: Path, capsys):
    out = resolve_actors.load_plugin_defaults(str(tmp_path / "nope"))
    assert out == []
    assert "not found" in capsys.readouterr().err


def test_load_plugin_defaults_tags_provenance(plugin_lib: Path):
    actors = resolve_actors.load_plugin_defaults(str(plugin_lib))
    assert len(actors) == 3
    assert all(a["_provenance"]["layer"] == "plugin" for a in actors)


def test_load_enterprise_actors_reads_glob(tmp_path: Path):
    profile = tmp_path / "profile"
    _write_yaml(
        profile / "actors" / "ent.yaml",
        {"actors": [{"id": "ENT-1", "label": "x"}]},
    )
    org = {"actors": {"inherit_defaults": False, "add": "actors/*.yaml", "disable": ["ACT-D-01"]}}
    actors, disables, inherit, add_glob = resolve_actors.load_enterprise_actors(org, str(profile))
    assert actors[0]["id"] == "ENT-1"
    assert actors[0]["_provenance"]["layer"] == "enterprise"
    assert inherit is False
    assert disables == [{"id": "ACT-D-01", "reason": None}]
    assert add_glob == "actors/*.yaml"


def test_load_enterprise_actors_bad_file_warns(tmp_path: Path, monkeypatch, capsys):
    profile = tmp_path / "profile"
    _write_yaml(profile / "actors" / "ent.yaml", {"actors": [{"id": "E"}]})
    monkeypatch.setattr(resolve_actors, "_load_yaml", lambda p: (_ for _ in ()).throw(ValueError("boom")))
    actors, *_ = resolve_actors.load_enterprise_actors({"actors": {}}, str(profile))
    assert actors == []
    assert "could not load" in capsys.readouterr().err


def test_load_enterprise_actors_defaults_when_empty():
    actors, disables, inherit, add_glob = resolve_actors.load_enterprise_actors({}, "")
    assert actors == [] and disables == [] and inherit is True
    assert add_glob == "actors/*.yaml"


def test_load_repo_actors_missing(tmp_path: Path):
    actors, disables, disc, inherit = resolve_actors.load_repo_actors(str(tmp_path / "nope"))
    assert actors == [] and disables == []
    assert disc == {"enabled": True, "max_proposed": 5}
    assert inherit is True


def test_load_repo_actors_with_rename_alias(tmp_path: Path):
    repo = tmp_path / "repo"
    _write_yaml(
        repo / ".appsec" / "actors.yaml",
        {
            "actors": [{"id": "NEW-1", "renamed_from": "OLD-1"}, {"id": "NEW-2", "renamed_from": ["O2", "O3"]}],
            "disable": [{"id": "X", "reason": "r"}],
            "discovery": {"enabled": False},
            "inherit_org": False,
        },
    )
    actors, disables, disc, inherit = resolve_actors.load_repo_actors(str(repo))
    assert actors[0]["_provenance"]["aliases"] == ["OLD-1"]
    assert actors[1]["_provenance"]["aliases"] == ["O2", "O3"]
    assert disables == [{"id": "X", "reason": "r"}]
    assert disc == {"enabled": False}
    assert inherit is False


# ---------------------------------------------------------------------------
# reach-equivalence
# ---------------------------------------------------------------------------
def test_apply_reach_equivalence_missing_lib(tmp_path: Path):
    rm = {"A": {"_provenance": {}}}
    out = resolve_actors.apply_reach_equivalence(rm, {}, str(tmp_path / "nope"))
    assert out is rm


def test_apply_reach_equivalence_collapses(plugin_lib: Path):
    rm = {
        "ACT-D-01": {"_provenance": {}},
        "ACT-D-02": {"_provenance": {}},
    }
    out = resolve_actors.apply_reach_equivalence(rm, {"has_open_self_registration": True}, str(plugin_lib))
    assert out["ACT-D-01"]["equivalent_to"] == ["ACT-D-01", "ACT-D-02"]
    assert out["ACT-D-01"]["collapse_primary"] == "ACT-D-01"
    assert out["ACT-D-01"]["_provenance"]["collapse_note"]


def test_apply_reach_equivalence_signal_off(plugin_lib: Path):
    rm = {"ACT-D-01": {"_provenance": {}}, "ACT-D-02": {"_provenance": {}}}
    out = resolve_actors.apply_reach_equivalence(rm, {}, str(plugin_lib))
    assert "equivalent_to" not in out["ACT-D-01"]


def test_apply_reach_equivalence_missing_actor(plugin_lib: Path):
    # rule requires both ids; only one present -> skip
    rm = {"ACT-D-01": {"_provenance": {}}}
    out = resolve_actors.apply_reach_equivalence(rm, {"has_open_self_registration": True}, str(plugin_lib))
    assert "equivalent_to" not in out["ACT-D-01"]


# ---------------------------------------------------------------------------
# resolve() — full integration
# ---------------------------------------------------------------------------
def _read(out_dir: Path, name: str) -> dict:
    return json.loads((out_dir / name).read_text())


def _discovery_doc(*proposals: dict) -> dict:
    return {
        "schema_version": 1,
        "discovery_cache_key": "a" * 64,
        "generated_at": "2026-06-30T12:00:00Z",
        "confirmed_relevant": [],
        "proposed_additional": list(proposals),
        "inputs_questioned": [],
        "coverage_rationale": "Static actors compared by access and authority.",
    }


def _proposal(**overrides) -> dict:
    proposal = {
        "id": "ACT-X-1",
        "label": "partner-api-credential-holder",
        "access": ["internet"],
        "trust_positions": ["partner-api-credential"],
        "distinct_trust_positions": ["partner-api-credential"],
        "distinct_trust_position_evidence": "Recon section 7.1 shows a partner-only API credential.",
        "capabilities": {
            "sophistication": "medium",
            "tooling": ["off-the-shelf"],
            "dwell_time": "weeks",
            "surface_reach": ["internet"],
        },
        "motivation": "financial",
        "rationale": "A partner credential grants authority unavailable to public or ordinary authenticated users.",
        "confidence": "high",
        "discovery_method": "heuristic-section-A",
    }
    proposal.update(overrides)
    return proposal


def test_resolve_basic_quick_mode(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        quick_mode=True,
    )
    assert (out / ".discovery-skipped.json").exists()
    assert (out / ".actor-fingerprints.json").exists()
    resolved = _read(out, ".actors-resolved.json")
    assert resolved["quick_mode"] is True
    # ACT-D-03 has no conditions -> always active; ACT-D-01/02 require signals -> warn-active
    ids = {a["id"] for a in resolved["resolved_actors"]}
    assert ids == {"ACT-D-01", "ACT-D-02", "ACT-D-03"}


def test_resolve_with_signals_activation(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    sig = tmp_path / "signals.json"
    sig.write_text(json.dumps({"signals": {"has_public_routes": True}}))
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        signals_path=str(sig),
        quick_mode=True,
    )
    merged = _read(out, ".actors-merged-static.json")
    active_ids = {a["id"] for a in merged["resolved_actors"]}
    # ACT-D-01 (has_public_routes) active; ACT-D-02 requires auth/role (any) -> inactive
    assert "ACT-D-01" in active_ids
    assert "ACT-D-03" in active_ids
    assert "ACT-D-02" not in active_ids
    assert {a["id"] for a in merged["catalog_actors"]} == {"ACT-D-01", "ACT-D-02", "ACT-D-03"}
    resolved = _read(out, ".actors-resolved.json")
    skipped = [i for i in resolved["run_issues"] if i["class"] == "default_actor_skipped"]
    assert any(i["actor_id"] == "ACT-D-02" for i in skipped)


def test_resolve_enterprise_and_repo_merge_and_disable(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    _write_yaml(
        repo / ".appsec" / "actors.yaml",
        {
            "actors": [{"id": "ACT-D-03", "label": "repo-override"}, {"id": "REPO-1", "access": ["internal"]}],
            "disable": [{"id": "ACT-D-01", "reason": "not relevant"}],
            "discovery": {"enabled": False},
        },
    )
    profile = tmp_path / "profile"
    org_path = profile / ".org-profile-effective.json"
    _write_yaml(profile / "actors" / "ent.yaml", {"actors": [{"id": "ENT-1", "access": ["dmz"]}]})
    profile.mkdir(exist_ok=True)
    org_path.write_text(
        json.dumps({"actors": {"add": "actors/*.yaml", "disable": [{"id": "ACT-D-02", "reason": "ent-off"}]}})
    )
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        org_profile_effective_path=str(org_path),
        quick_mode=True,
    )
    resolved = _read(out, ".actors-resolved.json")
    by_id = {a["id"]: a for a in resolved["resolved_actors"]}
    assert "ENT-1" in by_id and "REPO-1" in by_id
    # repo override merged into plugin ACT-D-03
    assert by_id["ACT-D-03"]["label"] == "repo-override"
    assert "repo" in by_id["ACT-D-03"]["_provenance"]["modified_by"]
    # disables applied
    assert by_id["ACT-D-01"]["_provenance"]["disabled_by"] == "repo"
    assert by_id["ACT-D-02"]["_provenance"]["disabled_by"] == "enterprise"


def test_resolve_disable_no_reason_emits_defect(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    _write_yaml(
        repo / ".appsec" / "actors.yaml",
        {"actors": [], "disable": ["ACT-D-01"], "discovery": {"enabled": False}},
    )
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        quick_mode=True,
    )
    resolved = _read(out, ".actors-resolved.json")
    defects = [i for i in resolved["run_issues"] if i["class"] == "disabled_actor_no_rationale"]
    assert any(i["actor_id"] == "ACT-D-01" for i in defects)


def test_resolve_repo_cannot_reenable_enterprise_disabled(plugin_lib: Path, tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    _write_yaml(
        repo / ".appsec" / "actors.yaml",
        {"actors": [], "disable": [{"id": "ACT-D-01", "reason": "repo-try"}], "discovery": {"enabled": False}},
    )
    profile = tmp_path / "profile"
    profile.mkdir()
    org_path = profile / ".org-profile-effective.json"
    org_path.write_text(json.dumps({"actors": {"disable": [{"id": "ACT-D-01", "reason": "ent"}]}}))
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        org_profile_effective_path=str(org_path),
        quick_mode=True,
    )
    err = capsys.readouterr().err
    assert "cannot re-enable" in err
    resolved = _read(out, ".actors-resolved.json")
    by_id = {a["id"]: a for a in resolved["resolved_actors"]}
    assert by_id["ACT-D-01"]["_provenance"]["disabled_by"] == "enterprise"


def test_resolve_inherit_org_false_excludes_enterprise(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    _write_yaml(
        repo / ".appsec" / "actors.yaml",
        {"actors": [], "inherit_org": False, "discovery": {"enabled": False}},
    )
    profile = tmp_path / "profile"
    profile.mkdir()
    org_path = profile / ".org-profile-effective.json"
    _write_yaml(profile / "actors" / "ent.yaml", {"actors": [{"id": "ENT-1", "access": ["dmz"]}]})
    org_path.write_text(json.dumps({"actors": {"add": "actors/*.yaml"}}))
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        org_profile_effective_path=str(org_path),
        quick_mode=True,
    )
    resolved = _read(out, ".actors-resolved.json")
    ids = {a["id"] for a in resolved["resolved_actors"]}
    assert "ENT-1" not in ids
    assert any(i["class"] == "repo_inherit_org_disabled" for i in resolved["run_issues"])


def test_resolve_discovery_layer(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    disc = tmp_path / "disc.json"
    disc.write_text(json.dumps(_discovery_doc(_proposal())))
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        discovery_output_path=str(disc),
        quick_mode=False,
    )
    resolved = _read(out, ".actors-resolved.json")
    by_id = {a["id"]: a for a in resolved["resolved_actors"]}
    assert resolved["discovery_actor_count"] == 1
    assert by_id["ACT-X-1"]["_provenance"]["layer"] == "discovery"
    assert by_id["ACT-X-1"]["_provenance"]["proposed"] is True
    assert by_id["ACT-X-1"]["heatmap_slug"] == "internet-user"
    assert resolved["rejected_discovery_actors"] == []


def test_resolve_rejects_discovery_actor_covered_by_static_access(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    disc = tmp_path / "disc.json"
    disc.write_text(
        json.dumps(
            _discovery_doc(
                _proposal(
                    label="technique-specialized-user",
                    access=["authenticated-user-session"],
                    trust_positions=["authenticated-user-authority"],
                    distinct_trust_positions=["authenticated-user-authority"],
                    distinct_trust_position_evidence="Recon shows the ordinary authenticated authority already in the static catalog.",
                )
            )
        )
    )
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        discovery_output_path=str(disc),
        quick_mode=False,
    )
    resolved = _read(out, ".actors-resolved.json")
    assert resolved["discovery_actor_count"] == 0
    assert resolved["rejected_discovery_actors"][0]["covered_by"] == "ACT-D-02"
    assert any(i["class"] == "discovery_actor_rejected" for i in resolved["run_issues"])


def test_discovery_gate_collapses_access_aliases():
    proposal = _proposal(
        access=["internet", "cloud-saas"],
        trust_positions=["llm-provider-control"],
        distinct_trust_positions=["llm-provider-control"],
    )
    static = [
        {
            "id": "ACT-D-07",
            "access": ["internet", "peer-service"],
            "trust_positions": ["trusted-service-control"],
        }
    ]
    reason, covered_by = resolve_actors._discovery_rejection_reason(
        proposal,
        static,
        {"cloud-saas": "peer-service", "peer-service": "peer-service"},
        {"llm-provider-control": "trusted-service-control", "trusted-service-control": "trusted-service-control"},
    )
    assert "already covered" in reason
    assert covered_by == "ACT-D-07"


def test_discovery_gate_compares_dormant_static_catalog():
    proposal = _proposal(
        label="assistant-config-author",
        access=["ci-cd-runtime"],
        trust_positions=["ai-assistant-config-write-authority"],
        distinct_trust_positions=["ai-assistant-config-write-authority"],
    )
    static = [
        {
            "id": "ACT-D-04",
            "access": ["ci-cd-runtime", "local-fs"],
            "trust_positions": ["source-repository-write-authority"],
            "_provenance": {"active": False},
        }
    ]
    reason, covered_by = resolve_actors._discovery_rejection_reason(
        proposal,
        static,
        {},
        {
            "ai-assistant-config-write-authority": "source-repository-write-authority",
            "source-repository-write-authority": "source-repository-write-authority",
        },
    )
    assert "already covered" in reason
    assert covered_by == "ACT-D-04"


@pytest.mark.parametrize(
    ("label", "access", "trust_position", "expected_actor"),
    [
        (
            "prompt-injector",
            ["authenticated-user-session"],
            "authenticated-user-authority",
            "ACT-D-02",
        ),
        (
            "llm-provider-adversary",
            ["internet", "cloud-saas"],
            "llm-provider-control",
            "ACT-D-07",
        ),
        (
            "ctf-competitor-security-researcher",
            ["authenticated-user-session"],
            "ctf-participant-authority",
            "ACT-D-02",
        ),
        (
            "ai-assistant-config-author",
            ["ci-cd-runtime"],
            "ai-assistant-config-write-authority",
            "ACT-D-04",
        ),
    ],
)
def test_incident_regression_rejects_technique_feature_and_persona_actors(
    label,
    access,
    trust_position,
    expected_actor,
):
    """Regression for the four bogus ACT-X classes emitted in the 2026-06-29 run."""
    proposal = _proposal(
        label=label,
        access=access,
        trust_positions=[trust_position],
        distinct_trust_positions=[trust_position],
    )
    static_catalog = [
        {
            "id": "ACT-D-02",
            "access": ["internet", "authenticated-user-session"],
            "trust_positions": ["authenticated-user-authority"],
        },
        {
            "id": "ACT-D-04",
            "access": ["local-fs", "ci-cd-runtime"],
            "trust_positions": ["source-repository-write-authority"],
            "_provenance": {"active": False},
        },
        {
            "id": "ACT-D-07",
            "access": ["internet", "peer-service"],
            "trust_positions": ["trusted-service-control"],
        },
    ]
    trust_aliases = {
        "authenticated-user-authority": "authenticated-user-authority",
        "ctf-participant-authority": "authenticated-user-authority",
        "source-repository-write-authority": "source-repository-write-authority",
        "ai-assistant-config-write-authority": "source-repository-write-authority",
        "trusted-service-control": "trusted-service-control",
        "llm-provider-control": "trusted-service-control",
    }
    reason, covered_by = resolve_actors._discovery_rejection_reason(
        proposal,
        static_catalog,
        {"cloud-saas": "peer-service", "peer-service": "peer-service"},
        trust_aliases,
    )
    assert "already covered" in reason
    assert covered_by == expected_actor


def test_incident_regression_full_resolver_rejects_all_four_proposals(
    plugin_lib: Path,
    tmp_path: Path,
):
    """Exercise schema validation, alias loading, dormant catalog, and merge together."""
    library_path = plugin_lib / "data" / "actors" / "default-library.yaml"
    library = yaml.safe_load(library_path.read_text())
    library["access_zone_aliases"] = {
        "peer-service": ["cloud-saas"],
    }
    library["trust_position_aliases"] = {
        "authenticated-user-authority": ["ctf-participant-authority"],
        "source-repository-write-authority": ["ai-assistant-config-write-authority"],
        "trusted-service-control": ["llm-provider-control"],
    }
    library["actors"].extend(
        [
            {
                "id": "ACT-D-04",
                "label": "malicious-insider-dev",
                "access": ["local-fs", "ci-cd-runtime"],
                "trust_positions": ["source-repository-write-authority"],
                "activation_conditions": {"required_signals": ["has_secrets_in_repo"]},
            },
            {
                "id": "ACT-D-07",
                "label": "compromised-third-party-service",
                "access": ["internet", "peer-service"],
                "trust_positions": ["trusted-service-control"],
                "activation_conditions": {"required_signals": ["has_external_apis"]},
            },
        ]
    )
    _write_yaml(library_path, library)

    proposals = [
        _proposal(
            id="ACT-X-1",
            label="prompt-injector",
            access=["authenticated-user-session"],
            trust_positions=["authenticated-user-authority"],
            distinct_trust_positions=["authenticated-user-authority"],
        ),
        _proposal(
            id="ACT-X-2",
            label="llm-provider-adversary",
            access=["internet", "cloud-saas"],
            trust_positions=["llm-provider-control"],
            distinct_trust_positions=["llm-provider-control"],
        ),
        _proposal(
            id="ACT-X-3",
            label="ctf-competitor-security-researcher",
            access=["authenticated-user-session"],
            trust_positions=["ctf-participant-authority"],
            distinct_trust_positions=["ctf-participant-authority"],
        ),
        _proposal(
            id="ACT-X-4",
            label="ai-assistant-config-author",
            access=["ci-cd-runtime"],
            trust_positions=["ai-assistant-config-write-authority"],
            distinct_trust_positions=["ai-assistant-config-write-authority"],
        ),
    ]
    discovery = tmp_path / "actors-discovered.json"
    discovery.write_text(json.dumps(_discovery_doc(*proposals)))
    signals = tmp_path / "signals.json"
    signals.write_text(
        json.dumps(
            {
                "signals": {
                    "has_public_routes": True,
                    "has_auth_surface": True,
                    "has_role_concept": True,
                    "has_secrets_in_repo": False,
                    "has_external_apis": True,
                }
            }
        )
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"

    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        discovery_output_path=str(discovery),
        signals_path=str(signals),
        quick_mode=False,
    )

    resolved = _read(out, ".actors-resolved.json")
    assert resolved["discovery_actor_count"] == 0
    assert not {a["id"] for a in resolved["resolved_actors"]} & {
        "ACT-X-1",
        "ACT-X-2",
        "ACT-X-3",
        "ACT-X-4",
    }
    rejected = {entry["id"]: entry.get("covered_by") for entry in resolved["rejected_discovery_actors"]}
    assert rejected == {
        "ACT-X-1": "ACT-D-02",
        "ACT-X-2": "ACT-D-07",
        "ACT-X-3": "ACT-D-02",
        "ACT-X-4": "ACT-D-04",
    }
    assert sum(issue["class"] == "discovery_actor_rejected" for issue in resolved["run_issues"]) == 4


def test_resolve_rejects_schema_invalid_discovery_output(plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    disc = tmp_path / "disc.json"
    disc.write_text(json.dumps({"schema_version": 1, "proposed_additional": []}))
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        discovery_output_path=str(disc),
        quick_mode=False,
    )
    resolved = _read(out, ".actors-resolved.json")
    assert resolved["discovery_actor_count"] == 0
    assert any(i["class"] == "invalid_actor_discovery_output" for i in resolved["run_issues"])


def test_resolve_discovery_bad_json_warns(plugin_lib: Path, tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    disc = tmp_path / "disc.json"
    disc.write_text("{not json")
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        discovery_output_path=str(disc),
        quick_mode=False,
    )
    assert "could not load discovery" in capsys.readouterr().err


def test_resolve_bad_signals_and_org_warn(plugin_lib: Path, tmp_path: Path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    sig = tmp_path / "sig.json"
    sig.write_text("{bad")
    org = tmp_path / "org.json"
    org.write_text("{bad")
    out = tmp_path / "out"
    resolve_actors.resolve(
        plugin_root=str(plugin_lib),
        repo_root=str(repo),
        output_dir=str(out),
        signals_path=str(sig),
        org_profile_effective_path=str(org),
        quick_mode=True,
    )
    err = capsys.readouterr().err
    assert "could not load signals" in err
    assert "could not load org-profile" in err


# ---------------------------------------------------------------------------
# CLI / main()
# ---------------------------------------------------------------------------
def test_cli_main(run_plugin_script, plugin_lib: Path, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    res = run_plugin_script(
        "resolve_actors.py",
        "--plugin-root",
        str(plugin_lib),
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out),
        "--quick",
        check=True,
    )
    assert res.returncode == 0
    assert (out / ".actors-resolved.json").exists()
